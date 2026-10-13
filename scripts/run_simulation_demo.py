"""Runnable APT attack-simulation demo for the ATT&CK Coverage Mapper.

End-to-end CLI that runs :func:`analysis.simulator.simulate_apt_attack` for
one or more APT groups against a populated ATT&CK database and prints a
coverage report:

1. Load ``config.yaml`` (platform scope, confidence threshold, enabled log
   sources).
2. Open the database (``DATABASE_URL`` env var, ``--database-url``, or the
   ``sqlite:///db/coverage.db`` default) and make sure the schema exists.
3. Idempotently populate ``technique_coverage`` from the mappings CSV.
4. Resolve the group via ``apt_groups.group_id``; for each non-revoked
   technique the group uses, classify it as ``detected`` /
   ``detected_rollup`` / ``missed`` against the enabled-datasource coverage
   rows, persist a :class:`~database.models.SimulationResult` plus one
   :class:`~database.models.SimulationTechnique` per technique, and emit a
   summary JSON.
5. Print the per-tactic coverage table, the per-technique status list, and
   the top-N greedy recommendations from
   :func:`analysis.simulator.generate_recommendations`.

Run from the repository root (any CWD works; paths resolve from this file):

    ./.venv/Scripts/python.exe scripts/run_simulation_demo.py G0016 [G0096 ...]

Expected Wave-2 simulator API (imported lazily so ``--help`` works before
the module lands; a missing symbol fails with exit code 3 and a precise
message instead of a traceback):

- ``analysis.simulator.simulate_apt_attack(group_id, session, *, persist=True)
  -> SimulationResult`` with fields ``id``, ``group_id``, ``run_at``,
  ``platform_scope``, ``confidence_threshold``, ``total_techniques``,
  ``detected_count``, ``missed_count``, ``coverage_pct``, ``summary``
  (dict), ``status``.
- ``analysis.simulator.generate_recommendations(result, session, top_n=3)``
  returning a list of human-readable recommendation strings.

Loader/parser/engine errors (FileNotFoundError, ValueError, ...) propagate
untouched so the demo never masks a broken pipeline. Exit codes: 0 on
success, 2 on argparse usage errors, 3 when a simulator module/symbol is
missing, 4 when the techniques table is empty and ``--load`` was not given.
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]

_SRC_DIR = REPO_ROOT / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from config_loader import load_config  # noqa: E402
from database.models import AttackMeta, Base, Technique  # noqa: E402
from database.session import database_url, make_engine, session_scope  # noqa: E402
from parser.mappings_io import load_mappings  # noqa: E402

if TYPE_CHECKING:  # pragma: no cover - static typing only
    from sqlalchemy.engine import Engine

logger = logging.getLogger(__name__)

CONFIG_PATH = REPO_ROOT / "config.yaml"
MAPPINGS_PATH = REPO_ROOT / "data" / "attack_mappings.csv"

#: Exit code used when the Wave-2 simulator module or symbol is missing.
EXIT_MISSING_ENGINE = 3
#: Exit code used when the techniques table is empty and --load was not given.
EXIT_EMPTY_DB = 4

#: Width of the ASCII coverage bar rendered next to each tactic percentage.
_BAR_WIDTH = 30


# --------------------------------------------------------------------------
# Lazy engine imports
# --------------------------------------------------------------------------

def _require(module: Any, attr: str, module_name: str) -> Any:
    """Return ``getattr(module, attr)`` or raise a precise ImportError.

    Keeps missing-symbol failures actionable: the message names the exact
    module, the expected symbol, and this script's documented API contract.
    """
    try:
        return getattr(module, attr)
    except AttributeError as exc:
        raise ImportError(
            f"module '{module_name}' does not expose '{attr}'; "
            f"run_simulation_demo.py expects the Wave-2 API documented in "
            f"this file's module docstring"
        ) from exc


def import_simulator() -> dict[str, Any]:
    """Import and return the Wave-2 simulator callables by name.

    Returns:
        Dict with keys ``simulate_apt_attack`` and
        ``generate_recommendations`` (from ``analysis.simulation``).

    Raises:
        ImportError: If the simulator module is absent or lacks an
            expected symbol.
    """
    try:
        from analysis import simulation as simulator
    except ImportError as exc:
        raise ImportError(
            f"simulator module not importable ({exc}); expected "
            f"src/analysis/simulator.py on PYTHONPATH"
        ) from exc
    return {
        "simulate_apt_attack": _require(
            simulator, "simulate_apt_attack", "analysis.simulation"),
        "generate_recommendations": _require(
            simulator, "generate_recommendations", "analysis.simulation"),
    }


# --------------------------------------------------------------------------
# Report sections
# --------------------------------------------------------------------------

def print_provenance(meta: AttackMeta | None, url: str) -> None:
    """Print the report header: database URL and ATT&CK snapshot pin."""
    print("ATT&CK Coverage Mapper - APT attack simulation")
    print(f"  database     : {url}")
    if meta is None:
        print("  snapshot     : (no attack_meta row)")
        return
    parts = []
    if meta.library_version:
        parts.append(f"mitreattack-python {meta.library_version}")
    if meta.bundle_version:
        parts.append(f"bundle v{meta.bundle_version}")
    if meta.bundle_date:
        parts.append(meta.bundle_date)
    print(f"  snapshot     : {' | '.join(parts) or 'unknown'}"
          f"  ({meta.object_count} objects)")


def render_bar(pct: float, width: int = _BAR_WIDTH) -> str:
    """Render a plain-text horizontal bar for a 0-100 percentage."""
    filled = max(0, min(width, round(pct / 100.0 * width)))
    return "#" * filled + "." * (width - filled)


def _isoformat(dt: datetime | None) -> str:
    """Return an ISO-8601 UTC string for a datetime, tolerating None."""
    if dt is None:
        return "(unknown)"
    return dt.astimezone(timezone.utc).isoformat()


def print_summary(result: Any) -> None:
    """Print the persisted SimulationResult scalar summary."""
    counts = result.summary.get("counts", {}) if isinstance(result.summary, dict) else {}
    print(f"Simulation result #{result.id}:")
    print(f"  group        : {result.group_id}")
    print(f"  run_at       : {_isoformat(result.run_at)}")
    print(f"  platform     : {result.platform_scope}")
    print(f"  threshold    : {result.confidence_threshold}")
    print(f"  total        : {result.total_techniques}")
    print(f"  detected     : {counts.get('detected', result.detected_count)}")
    print(f"  rollup       : {counts.get('detected_rollup', 0)}")
    print(f"  missed       : {counts.get('missed', result.missed_count)}")
    print(f"  coverage     : {result.coverage_pct:.2%}")
    print()


def print_tactic_table(result: Any) -> None:
    """Print the per-tactic detectability table from the summary JSON."""
    per_tactic = (
        result.summary.get("per_tactic", {})
        if isinstance(result.summary, dict)
        else {}
    )
    if not per_tactic:
        print("Per-tactic breakdown: (none)")
        return
    ordered = [
        "reconnaissance", "resource-development", "initial-access",
        "execution", "persistence", "privilege-escalation", "defense-evasion",
        "credential-access", "discovery", "lateral-movement", "collection",
        "command-and-control", "exfiltration", "impact",
    ]
    print("Per-tactic breakdown:")
    print(f"  {'tactic':<22}{'total':>6}{'detect':>8}{'miss':>7}  {'pct':>6}  bar")
    for tactic in ordered:
        bucket = per_tactic.get(tactic)
        if not bucket:
            continue
        total = bucket.get("total", 0)
        detected = bucket.get("detected", 0)
        missed = bucket.get("missed", 0)
        pct = (100.0 * detected / total) if total else 0.0
        print(f"  {tactic:<22}{total:>6}{detected:>8}{missed:>7}  "
              f"{pct:>5.1f}%  {render_bar(pct)}")
    print()


def print_techniques(records: Sequence[Any], limit: int) -> None:
    """Print the per-technique status rows, grouped by status.

    Args:
        records: ``SimulationTechnique`` rows for the result, sorted by
            ``(status, technique_attack_id)``.
        limit: Maximum number of rows to show per status bucket; a note
            is printed when the bucket is truncated.
    """
    if not records:
        print("Techniques: (none)")
        return
    buckets: dict[str, list[Any]] = {"detected": [], "detected_rollup": [], "missed": []}
    for rec in records:
        buckets.setdefault(rec.status, []).append(rec)
    for status in ("detected", "detected_rollup", "missed"):
        rows = buckets.get(status, [])
        if not rows:
            continue
        print(f"{status} ({len(rows)}):")
        shown = rows[:max(0, limit)]
        for rec in shown:
            sources = ", ".join(rec.contributing_sources or []) or "-"
            conf = f"{rec.confidence:.2f}" if rec.confidence is not None else "-"
            print(f"  {rec.technique_attack_id} {rec.name or ''}"
                  f"  [{rec.tactic or '-'}]  conf={conf}  sources={sources}")
        if len(rows) > len(shown):
            print(f"  ... and {len(rows) - len(shown)} more")
        print()


def print_recommendations(recommendations: Sequence[str]) -> None:
    """Print the greedy marginal-gain recommendations."""
    if not recommendations:
        print("Recommendations: none.")
        return
    print(f"Recommendations (top {len(recommendations)}):")
    for line in recommendations:
        print(f"  - {line}")
    print()


# --------------------------------------------------------------------------
# Pipeline
# --------------------------------------------------------------------------

def ensure_techniques(session: Any, allow_load: bool) -> bool:
    """Make sure the techniques table is non-empty, loading from cache if asked.

    Returns True when the table holds techniques; False when it is empty and
    the caller should stop with EXIT_EMPTY_DB.
    """
    count = session.query(Technique).count()
    if count:
        logger.info("techniques table holds %d rows", count)
        return True
    if not allow_load:
        return False
    from attack_data.loader import load_all

    logger.info("empty techniques table; loading ATT&CK from local cache ...")
    load_report = load_all(session)
    logger.info(
        "loader done: %s", getattr(load_report, "counts", {}) or "no counts",
    )
    return bool(session.query(Technique).count())


def run_simulation(args: argparse.Namespace, api: dict[str, Any],
                   config: dict[str, object], engine: Any) -> int:
    """Execute the demo pipeline for the requested groups; return exit code."""
    with session_scope(engine) as session:
        meta = session.query(AttackMeta).order_by(AttackMeta.id.desc()).first()
        print_provenance(meta, args.database_url or database_url())

        if not ensure_techniques(session, allow_load=args.load):
            logger.error(
                "techniques table is empty; run the Phase-1 loader first "
                "or re-run this script with --load",
            )
            return EXIT_EMPTY_DB

        rules = load_mappings(str(args.mappings))
        from analysis import coverage_analyzer

        coverage_analyzer.populate_technique_coverage(session, rules, config)

        print(f"platform_scope : {config['platform_scope']}")
        print(f"threshold      : {config['detection_confidence_threshold']}")
        sources = ", ".join(
            f"{fmt}={str(on).lower()}"
            for fmt, on in sorted(
                (config.get("enabled_log_sources") or {}).items()
            )
        )
        print(f"sources        : {sources}")
        print()

        for group_id in args.group_id:
            print(f"===== Simulating {group_id} =====")
            try:
                result = api["simulate_apt_attack"](
                    group_id, session, persist=True
                )
            except ValueError as exc:
                # Unknown group_id: surface the engine's message (lists
                # valid ids) and continue to the next group.
                print(f"  {exc}")
                print()
                continue
            print_summary(result)
            print_tactic_table(result)

            # Reload the SimulationTechnique rows for display. The result
            # object itself does not carry them, so query by result_id.
            from database.models import SimulationTechnique

            records = (
                session.query(SimulationTechnique)
                .filter(SimulationTechnique.result_id == result.id)
                .order_by(
                    SimulationTechnique.status,
                    SimulationTechnique.technique_attack_id,
                )
                .all()
            )
            print_techniques(records, limit=args.top)

            recs = api["generate_recommendations"](
                result, session, top_n=args.recommend
            )
            print_recommendations(recs)
    return 0


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser (kept separate for testability)."""
    parser = argparse.ArgumentParser(
        prog="run_simulation_demo.py",
        description="Phase 4 demo: simulate APT attacks against the coverage "
                    "engine and print per-group detection reports.",
    )
    parser.add_argument(
        "group_id", nargs="+",
        help="one or more ATT&CK group ids to simulate (e.g. G0016 G0096 G0032)",
    )
    parser.add_argument("--config", default=str(CONFIG_PATH),
                        help=f"config YAML path (default: {CONFIG_PATH})")
    parser.add_argument("--database-url", default=None,
                        help="SQLAlchemy URL override (default: DATABASE_URL "
                             "env or sqlite:///db/coverage.db)")
    parser.add_argument("--mappings", default=str(MAPPINGS_PATH),
                        help=f"attack_mappings.csv path (default: {MAPPINGS_PATH})")
    parser.add_argument("--threshold", type=float, default=None,
                        help="override detection_confidence_threshold [0.0-1.0]")
    parser.add_argument("--top", type=int, default=15,
                        help="max technique rows shown per status bucket "
                             "(default: 15)")
    parser.add_argument("--recommend", type=int, default=3,
                        help="number of greedy recommendations to show "
                             "(default: 3)")
    parser.add_argument("--load", action="store_true",
                        help="when the techniques table is empty, load ATT&CK "
                             "from the local STIX cache first")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="INFO-level diagnostics on stderr")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point: configure logging, run the pipeline, map known failures.

    Simulator-module absence becomes exit code 3 with a precise message;
    every other loader/parser/engine exception propagates untouched.
    """
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )
    config = load_config(args.config)
    if args.threshold is not None:
        if isinstance(args.threshold, bool) or not 0.0 <= args.threshold <= 1.0:
            raise ValueError(
                f"--threshold must be within [0.0, 1.0], got {args.threshold!r}"
            )
        config["detection_confidence_threshold"] = args.threshold

    url = args.database_url or database_url()
    engine: Engine = make_engine(url)
    Base.metadata.create_all(engine)  # idempotent; enables fresh SQLite files

    try:
        api = import_simulator()
    except ImportError as exc:
        logger.error("%s", exc)
        return EXIT_MISSING_ENGINE

    try:
        return run_simulation(args, api, config, engine)
    except ImportError as exc:
        # Only reachable for engine-side import problems.
        logger.error("%s", exc)
        return EXIT_MISSING_ENGINE


if __name__ == "__main__":
    raise SystemExit(main())
