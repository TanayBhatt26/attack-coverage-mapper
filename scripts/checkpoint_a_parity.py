#!/usr/bin/env python3
"""Checkpoint A parity harness: SQLite vs PostgreSQL for ATT&CK Coverage Mapper.

Drives the *identical* data pipeline against two database backends and proves
the resulting contents match, so the submission claim "SQLite-first dev,
Dockerized Postgres validated at checkpoints" is backed by evidence.

Pipeline executed per backend (in a fresh schema):

1. Fresh schema. PostgreSQL: ``DROP SCHEMA public CASCADE`` + ``CREATE SCHEMA``
   first (removes stray views/sequences the ORM does not know about), then
   ``Base.metadata.drop_all()`` + ``create_all()``. SQLite: drop/create of the
   ten ORM-managed tables only. NOTE: this destroys existing rows in the
   target schema -- the default URLs point at the disposable dev SQLite DB and
   the docker-compose Postgres, both rebuildable from the local STIX cache.
2. ``attack_data.loader.load_all(session)`` (cache-first; network only if the
   cache at ``data/attack_stix/enterprise-attack.json`` is missing).
3. ``populate_technique_coverage(...)`` (Phase-3 Wave-2 module). Because waves
   land in parallel, the import is resolved lazily from a short candidate list
   (see ``POPULATE_IMPORT_CANDIDATES``); a missing module aborts cleanly with
   exit code 1 *before* any schema is touched.

Comparison rules (deterministic, order-independent):

* Per table, rows become multiset of SHA-256 signatures over canonicalized
  column values (see ``_normalize_value``): datetimes -> UTC-aware ISO-8601,
  JSON -> ``json.dumps(sort_keys=True)`` (semantic compare, immune to key
  order), floats/Decimals via ``repr(float(v))``, everything else repr'd.
* Surrogate autoincrement PKs (single integer ``id`` columns) are excluded
  from the signature; child FK values pointing at such PKs are rewritten
  through the parent's natural-content signature before hashing (tables are
  visited in ``metadata.sorted_tables`` dependency order). This forgives
  benign renumbering while still catching wrong joins and wrong contents.
* Known unstable columns -- server/clock-generated timestamps written at load
  time (``attack_meta.loaded_at``, ``simulation_results.run_at``) -- are
  excluded outright: normalization cannot make two different wall-clock
  instants equal.
* First differing row per table is printed on mismatch (truncated).

Usage::

    python scripts/checkpoint_a_parity.py                     # both defaults
    python scripts/checkpoint_a_parity.py --sqlite sqlite:///tmp/a.db
    python scripts/checkpoint_a_parity.py --skip-populate     # loader-only

Exit codes: 0 = full parity; 2 = content mismatch; 1 = operational failure
(bad config, unreachable backend, driver missing, populate module absent).
Usage errors also exit 1 (argparse default of 2 is overridden so that 2
exclusively means "parity failed").

Pure stdlib + SQLAlchemy. Never executes hunt queries: nothing from
``detections/`` or pySigma is imported. Requires the Postgres service from
``docker-compose.yml`` (user/db/pass attack_mapper) for the default PG URL;
after a schema drop, re-run the initdb grant script if non-owner roles need
access again.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import logging
import sys
import time
from collections import Counter
from dataclasses import dataclass
from datetime import date, datetime, time as dt_time, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Callable

from sqlalchemy import JSON, Column, Date, DateTime, Integer, Time, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.sql.type_api import TypeEngine

logger = logging.getLogger("checkpoint_a_parity")

PROJECT_ROOT = Path(__file__).resolve().parents[1]

DEFAULT_SQLITE_URL = "sqlite:///db/_parity_sqlite.db"
DEFAULT_POSTGRES_URL = (
    "postgresql+psycopg://attack_mapper:REPLACE_FROM_ENV@localhost:5432/attack_coverage"
)
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config.yaml"
DEFAULT_CSV_PATH = PROJECT_ROOT / "data" / "attack_mappings.csv"

# Clock-written columns whose values legitimately differ between the two
# sequential pipeline runs; normalization cannot reconcile distinct instants.
UNSTABLE_COLUMNS = frozenset(
    {("attack_meta", "loaded_at"), ("simulation_results", "run_at")}
)

# Where the Phase-3 Wave-2 populate implementation is expected to live.
# First module exposing ``populate_technique_coverage`` wins.
POPULATE_IMPORT_CANDIDATES = (
    "analysis.coverage_analyzer",
    "analysis.populate",
    "database.populate",
)

_SENTINEL_UNRESOLVED = "!fk-unresolved:{value}!"
_FIELD_TRUNCATE = 80
_NOTE_MAX = 600


class _ArgumentParser(argparse.ArgumentParser):
    """argparse parser whose usage errors exit 1, keeping exit 2 for mismatches."""

    def error(self, message: str) -> None:  # noqa: D102 - argparse hook
        self.print_usage(sys.stderr)
        self.exit(1, f"{self.prog}: error: {message}\n")


@dataclass(frozen=True)
class TableDiff:
    """Outcome of comparing one table across the two databases."""

    table: str
    count_left: int
    count_right: int
    note: str | None


@dataclass(frozen=True)
class ParityReport:
    """Aggregate comparison result across all ORM tables."""

    diffs: tuple[TableDiff, ...]

    @property
    def ok(self) -> bool:
        return not self.diffs


def _label(engine: Engine) -> str:
    """Human-safe engine label (password masked)."""
    return engine.url.render_as_string(hide_password=True)


def _is_postgresql(url: str) -> bool:
    return url.strip().lower().startswith(("postgresql+", "postgresql:", "postgres:"))


def _connectable(engine: Engine) -> None:
    """Raise a descriptive error unless ``SELECT 1`` works on ``engine``."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:
        if _is_postgresql(engine.url.render_as_string(hide_password=True)):
            raise RuntimeError(
                f"cannot reach PostgreSQL at {_label(engine)}: {exc}\n"
                "hint: start the container with 'docker compose up -d postgres'"
            ) from exc
        raise RuntimeError(
            f"cannot open database {_label(engine)}: {exc}"
        ) from exc


def reset_schema(engine: Engine) -> None:
    """Drop and recreate a fresh application schema on ``engine``.

    PostgreSQL: ``DROP SCHEMA public CASCADE`` + ``CREATE SCHEMA public`` in
    one transaction (clears ORM-foreign leftovers), then metadata drop/create.
    Other backends: metadata drop/create only. Destructive by design; callers
    must only point this at disposable databases.
    """
    from database.models import Base  # lazy: keep module import cheap

    if _is_postgresql(_dialect_url(engine)):
        logger.warning("Dropping and recreating schema public on %s", _label(engine))
        with engine.begin() as conn:
            conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            conn.execute(text("CREATE SCHEMA public"))
    logger.warning("Recreating all ORM tables on %s", _label(engine))
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)


def _dialect_url(engine: Engine) -> str:
    return engine.url.drivername


def _load_config(path: Path) -> dict:
    """Load the normalized app config (lazy import of ``config_loader``)."""
    sys.path.insert(0, str(PROJECT_ROOT / "src"))
    from config_loader import load_config

    return load_config(str(path))


def _import_populate() -> Callable[..., object]:
    """Resolve ``populate_technique_coverage`` from the Wave-2 candidates."""
    sys.path.insert(0, str(PROJECT_ROOT / "src"))
    errors: list[str] = []
    for modname in POPULATE_IMPORT_CANDIDATES:
        try:
            module = importlib.import_module(modname)
        except ImportError as exc:  # module absent (parallel wave) or broken
            errors.append(f"{modname}: {exc}")
            continue
        fn = getattr(module, "populate_technique_coverage", None)
        if callable(fn):
            logger.debug("Using populate implementation from %s", modname)
            return fn
        errors.append(f"{modname}: no callable populate_technique_coverage")
    raise ImportError(
        "populate_technique_coverage not found; tried:\n  " + "\n  ".join(errors)
    )


def _report_summary(report: object) -> str:
    """Best-effort one-line summary of a LoadReport/PopulateReport.

    Field shapes are owned by sibling deliverables; unknown attributes render
    as ``?`` instead of crashing the harness.
    """
    if report is None:
        return "<no report>"
    interesting = (
        "rows_upserted",
        "rows_inserted",
        "rows_updated",
        "rows_deleted",
        "skipped_revoked",
        "skipped_orphan",
        "warnings",
        "counts",
    )
    parts = [
        f"{name}={getattr(report, name, '?')}" for name in interesting
        if hasattr(report, name)
    ]
    return ", ".join(parts) if parts else repr(report)


def run_pipeline(
    engine: Engine, cfg: dict, csv_path: Path, populate_fn: Callable[..., object]
) -> str:
    """Run loader-from-cache + populate against one engine; return a summary."""
    from database.session import session_scope
    from attack_data.loader import load_all

    started = time.perf_counter()
    with session_scope(engine) as session:
        load_report = load_all(session)
    load_seconds = time.perf_counter() - started

    populate_summary = "<skipped>"
    if populate_fn is not None:
        from parser.mappings_io import load_mappings

        rules = load_mappings(csv_path)
        started = time.perf_counter()
        with session_scope(engine) as session:
            populate_report = populate_fn(session, rules, cfg)
        populate_summary = _report_summary(populate_report)
        logger.info("populate took %.2fs", time.perf_counter() - started)
    logger.info("load_all took %.2fs", load_seconds)
    return f"load[{_report_summary(load_report)}] populate[{populate_summary}]"


def _surrogate_pk(table) -> Column | None:
    """Single integer ``id`` PK column treated as unstable surrogate, or None."""
    pk = list(table.primary_key.columns)
    if len(pk) == 1 and pk[0].name == "id" and isinstance(pk[0].type, Integer):
        if not pk[0].foreign_keys:
            return pk[0]
    return None


def _fk_targets(table) -> dict[str, tuple[str, str]]:
    """Map column name -> (referenced table, referenced column) for ``table``."""
    out: dict[str, tuple[str, str]] = {}
    for column in table.columns:
        for fk in column.foreign_keys:
            target = fk.column
            out[column.name] = (target.table.name, target.name)
    return out


def _normalize_value(value: object, type_: TypeEngine) -> str:
    """Canonical string for one cell, safe to hash across both backends.

    Datetimes become UTC-aware ISO-8601 (naive assumed UTC -- SQLite loses
    the offset), JSON becomes sorted-key compact dumps (semantic compare),
    floats/Decimals go through ``repr(float(v))``, bytes hex, everything else
    is repr'd. Booleans are tested before ints (bool subclasses int).
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return repr(value)
    if isinstance(value, datetime):
        aware = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
        return aware.astimezone(timezone.utc).isoformat()
    if isinstance(value, (date, dt_time, datetime, timedelta)):
        return value.isoformat() if not isinstance(value, timedelta) else str(value)
    if isinstance(type_, (DateTime, Date, Time)):
        # Timestamp stored as raw string on some drivers: keep it comparable.
        return json.dumps(str(value), ensure_ascii=True)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    if isinstance(type_, JSON):
        payload = value
        if isinstance(payload, (str, bytes, bytearray)):
            try:
                payload = json.loads(payload)
            except ValueError:
                payload = str(value)
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            default=str,
        )
    if isinstance(value, Decimal):
        return repr(float(value))
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, int):
        return str(value)
    return json.dumps(str(value), ensure_ascii=True)


def _truncate(value: str, limit: int = _FIELD_TRUNCATE) -> str:
    return value if len(value) <= limit else value[: limit - 3] + "..."


class _TableFingerprinter:
    """Builds per-table row signature multisets with FK canonicalization.

    For each table (visited in ``metadata.sorted_tables`` order, i.e. parents
    before children): rows are hashed over every column except unstable
    columns and a surrogate ``id`` PK. When a child column references a
    parent's surrogate PK, the value is replaced by the parent row's natural
    signature hash, so renumbered surrogates never cause false mismatches
    while wrong joins still do.
    """

    def __init__(self, engine: Engine) -> None:
        from database.models import Base  # lazy

        self._engine = engine
        self._tables = Base.metadata.sorted_tables
        self._pk_maps: dict[str, dict[object, str]] = {}

    def tables(self):
        return self._tables

    def fingerprints(
        self, table
    ) -> tuple[Counter[str], dict[str, tuple[str, ...]]]:
        """Return ({sig: count}, {sig: display tuple}) for ``table``."""
        surrogate = _surrogate_pk(table)
        fk_map = _fk_targets(table)
        counts: Counter[str] = Counter()
        display: dict[str, tuple[str, ...]] = {}
        with self._engine.connect() as conn:
            for row in conn.execute(select(table)).mappings():
                cells: list[str] = []
                shown: list[str] = []
                for column in table.columns:
                    if (table.name, column.name) in UNSTABLE_COLUMNS:
                        continue
                    if surrogate is not None and column.name == surrogate.name:
                        continue
                    value = row[column.name]
                    target = fk_map.get(column.name)
                    if target is not None:
                        parent_map = self._pk_maps.get(target[0])
                        if parent_map is not None and target[1] == "id":
                            value = parent_map.get(
                                value, _SENTINEL_UNRESOLVED.format(value=value)
                            )
                    canonical = _normalize_value(value, column.type)
                    cells.append(f"{column.name}\x1f{canonical}")
                    shown.append(f"{column.name}={_truncate(canonical)}")
                signature = hashlib.sha256(
                    json.dumps(cells, ensure_ascii=True).encode("utf-8")
                ).hexdigest()
                counts[signature] += 1
                display.setdefault(signature, tuple(shown))
                if surrogate is not None:
                    self._pk_maps.setdefault(table.name, {})[
                        row[surrogate.name]
                    ] = signature
        return counts, display


def _first_difference_note(
    table_name: str,
    left_label: str,
    right_label: str,
    left_counts: Counter[str],
    right_counts: Counter[str],
    left_display: dict[str, tuple[str, ...]],
    right_display: dict[str, tuple[str, ...]],
) -> str:
    """Describe the first differing row deterministically (sorted by sig)."""
    only_left = sorted(left_counts - right_counts)
    only_right = sorted(right_counts - left_counts)
    head = (
        f"{len(only_left)} row(s) only in {left_label}, "
        f"{len(only_right)} row(s) only in {right_label}"
    )
    if only_left:
        sig = only_left[0]
        head += f"; first differing row ({left_label}): {left_display[sig]}"
    elif only_right:
        sig = only_right[0]
        head += f"; first differing row ({right_label}): {right_display[sig]}"
    return head[:_NOTE_MAX]


def compare_databases(left: Engine, right: Engine) -> ParityReport:
    """Compare every ORM table between the two engines; return the report."""
    left_fp = _TableFingerprinter(left)
    right_fp = _TableFingerprinter(right)
    left_label, right_label = _label(left), _label(right)
    if [t.name for t in left_fp.tables()] != [t.name for t in right_fp.tables()]:
        raise RuntimeError("the two engines expose different ORM metadata")
    diffs: list[TableDiff] = []
    for table in left_fp.tables():
        left_counts, left_display = left_fp.fingerprints(table)
        right_counts, right_display = right_fp.fingerprints(table)
        if left_counts == right_counts:
            logger.info(
                "table %-24s PARITY (%d rows)", table.name, sum(left_counts.values())
            )
            continue
        note = _first_difference_note(
            table.name, left_label, right_label,
            left_counts, right_counts, left_display, right_display,
        )
        logger.error("table %-24s MISMATCH: %s", table.name, note)
        diffs.append(
            TableDiff(
                table=table.name,
                count_left=sum(left_counts.values()),
                count_right=sum(right_counts.values()),
                note=note,
            )
        )
    return ParityReport(diffs=tuple(diffs))


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments (defaults per the Checkpoint A contract)."""
    parser = _ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--sqlite", default=DEFAULT_SQLITE_URL,
        help=f"left DATABASE_URL (default: {DEFAULT_SQLITE_URL})",
    )
    parser.add_argument(
        "--postgres", default=DEFAULT_POSTGRES_URL,
        help=f"right DATABASE_URL (default: {DEFAULT_POSTGRES_URL})",
    )
    parser.add_argument(
        "--config", type=Path, default=DEFAULT_CONFIG_PATH,
        help="config.yaml path (default: repo config.yaml)",
    )
    parser.add_argument(
        "--csv", type=Path, default=DEFAULT_CSV_PATH,
        help="attack_mappings.csv path (default: data/attack_mappings.csv)",
    )
    parser.add_argument(
        "--skip-populate", action="store_true",
        help="run the loader only (debug aid); populate normally required",
    )
    parser.add_argument("--verbose", action="store_true", help="DEBUG logging")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Entry point; see module docstring for contract and exit codes."""
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        stream=sys.stdout,
    )
    import sqlalchemy

    logger.info(
        "Checkpoint A parity harness | python %s | sqlalchemy %s",
        sys.version.split()[0], sqlalchemy.__version__,
    )

    try:
        cfg = _load_config(args.config)
    except FileNotFoundError as exc:
        logger.error("config file missing: %s", exc)
        return 1
    except ValueError as exc:
        logger.error("invalid config: %s", exc)
        return 1

    try:
        populate_fn = None if args.skip_populate else _import_populate()
    except ImportError as exc:
        logger.error("%s", exc)
        return 1

    from database.session import make_engine

    engines: list[Engine] = []
    for url in (args.sqlite, args.postgres):
        try:
            engine = make_engine(url)
            _connectable(engine)
        except Exception as exc:
            logger.error("%s", exc)
            return 1
        engines.append(engine)
    left, right = engines

    try:
        for engine in (left, right):
            reset_schema(engine)
            logger.info(
                "pipeline on %s -> %s",
                _label(engine),
                run_pipeline(engine, cfg, args.csv, populate_fn),
            )
        report = compare_databases(left, right)
    except Exception as exc:  # operational failure, not a parity verdict
        logger.error("harness failure: %s", exc, exc_info=args.verbose)
        return 1

    if report.ok:
        print("CHECKPOINT A PARITY OK: all tables identical across backends")
        return 0
    for diff in report.diffs:
        print(f"MISMATCH {diff.table}: left={diff.count_left} right={diff.count_right}")
        if diff.note:
            print(f"  {diff.note}")
    print(f"CHECKPOINT A PARITY FAILED: {len(report.diffs)} table(s) differ")
    return 2


if __name__ == "__main__":
    sys.exit(main())
