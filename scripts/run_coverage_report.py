"""Runnable Phase 3 coverage report demo for the ATT&CK Coverage Mapper.

End-to-end CLI walkthrough of the coverage engine against a populated
ATT&CK database:

1. Load ``config.yaml`` (platform scope, confidence threshold, enabled
   log sources, optional ``clustering`` block).
2. Open the database (``DATABASE_URL`` env var, ``--database-url``, or the
   ``sqlite:///db/coverage.db`` default) and make sure the schema exists.
3. Run the idempotent ``technique_coverage`` population step (mappings CSV
   x enabled datasources x resolvable techniques), reporting inserted /
   updated / deleted / skipped row counts.
4. Print the per-tactic detectability table (all 14 Enterprise tactics,
   canonically ordered, scoped to the configured platform scope).
5. List the undetected-technique gaps (with honest ``closable_by`` source
   hints) and cluster them via the KMeans gap-clustering layer.

Run from the repository root (any CWD works; paths resolve from this file):

    ./.venv/Scripts/python.exe scripts/run_coverage_report.py [--help]

Expected Wave-2 engine API (imported lazily so ``--help`` works before the
engine modules land; a missing symbol fails with exit code 3 and a precise
message instead of a traceback):

- ``analysis.coverage_analyzer.populate_technique_coverage(
    session, cfg, *, csv_path=..., threshold=None) -> PopulateReport``
  with frozen fields ``(rows_upserted, rows_inserted, rows_updated,
  rows_deleted, skipped_revoked, skipped_orphan, warnings)``.
- ``analysis.coverage_analyzer.coverage_by_tactic(session, cfg)``
  returning a tuple of ``TacticCoverage(tactic, total, detectable, pct)``
  sorted in canonical ATT&CK order, all 14 tactics emitted.
- ``analysis.coverage_analyzer.calculate_coverage_gaps(session, cfg)``
  returning a tuple of ``Gap(technique_attack_id, name, tactic,
  best_confidence, closable_by)`` sorted by (tactic, confidence asc).
- ``analysis.gap_clustering.cluster_gaps(gaps, cfg)`` returning a tuple of
  ``GapCluster(cluster_id, label, technique_ids, summary, size)``.

Loader/parser/engine errors (FileNotFoundError, ValueError, ...) propagate
untouched so the demo never masks a broken pipeline. Exit codes: 0 on
success, 2 on argparse usage errors, 3 when an engine module/symbol is
missing, 4 when the techniques table is empty and ``--load`` was not given.
"""

from __future__ import annotations

import argparse
import logging
import sys
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

#: Exit code used when a Wave-2 engine module or symbol is missing.
EXIT_MISSING_ENGINE = 3
#: Exit code used when the techniques table is empty and --load was not given.
EXIT_EMPTY_DB = 4

#: Width of the ASCII coverage bar rendered next to each tactic percentage.
_BAR_WIDTH = 40


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
            f"run_coverage_report.py expects the Wave-2 API documented in "
            f"this file's module docstring"
        ) from exc


def import_coverage_engine() -> dict[str, Any]:
    """Import and return the Wave-2 coverage-engine callables by name.

    Returns:
        Dict with keys ``populate_technique_coverage``,
        ``coverage_by_tactic``, ``calculate_coverage_gaps`` (from
        ``analysis.coverage_analyzer``) and ``cluster_gaps`` (from
        ``analysis.gap_clustering``).

    Raises:
        ImportError: If either engine module is absent or lacks an
            expected symbol.
    """
    try:
        from analysis import coverage_analyzer
        from analysis import gap_clustering
    except ImportError as exc:
        raise ImportError(
            f"coverage engine modules not importable ({exc}); expected "
            f"src/analysis/coverage_analyzer.py and src/analysis/"
            f"gap_clustering.py on PYTHONPATH"
        ) from exc
    return {
        "populate_technique_coverage": _require(
            coverage_analyzer, "populate_technique_coverage",
            "analysis.coverage_analyzer"),
        "load_coverage_rows": _require(
            coverage_analyzer, "load_coverage_rows",
            "analysis.coverage_analyzer"),
        "coverage_by_tactic": _require(
            coverage_analyzer, "coverage_by_tactic",
            "analysis.coverage_analyzer"),
        "calculate_coverage_gaps": _require(
            coverage_analyzer, "calculate_coverage_gaps",
            "analysis.coverage_analyzer"),
        "cluster_gaps": _require(gap_clustering, "cluster_gaps",
                                 "analysis.gap_clustering"),
    }


# --------------------------------------------------------------------------
# Report sections
# --------------------------------------------------------------------------

def print_provenance(meta: AttackMeta | None, url: str) -> None:
    """Print the report header: database URL and ATT&CK snapshot pin."""
    print("ATT&CK Coverage Mapper - coverage report")
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


def print_populate_summary(report: Any) -> None:
    """Print the idempotent populate outcome (contract-C PopulateReport)."""
    skipped_revoked = tuple(getattr(report, "skipped_revoked", ()) or ())
    skipped_orphan = tuple(getattr(report, "skipped_orphan", ()) or ())
    print("Population (mappings x enabled datasources):")
    print(f"  pairs upserted : {report.rows_upserted}"
          f"  (inserted {report.rows_inserted}, updated {report.rows_updated},"
          f" deleted {report.rows_deleted})")
    if skipped_revoked:
        print(f"  skipped revoked/deprecated techniques ({len(skipped_revoked)}):"
              f" {', '.join(skipped_revoked)}")
    if skipped_orphan:
        print(f"  skipped unresolvable mappings ({len(skipped_orphan)}):"
              f" {', '.join(skipped_orphan)}")
    if report.warnings:
        print(f"  warnings       : {report.warnings}")
    logger.debug(
        "populate report: upserted=%d inserted=%d updated=%d deleted=%d "
        "skipped_revoked=%s skipped_orphan=%s warnings=%d",
        report.rows_upserted, report.rows_inserted, report.rows_updated,
        report.rows_deleted, skipped_revoked, skipped_orphan, report.warnings,
    )


def render_bar(pct: float, width: int = _BAR_WIDTH) -> str:
    """Render a plain-text horizontal bar for a 0-100 percentage."""
    filled = max(0, min(width, round(pct / 100.0 * width)))
    return "#" * filled + "." * (width - filled)


def print_tactic_table(tactics: Iterable[Any]) -> None:
    """Print the per-tactic detectability table in returned (canonical) order."""
    rows = list(tactics)
    total_all = sum(row.total for row in rows)
    detected_all = sum(row.detectable for row in rows)
    overall = 100.0 * detected_all / total_all if total_all else 0.0
    print(f"Tactic coverage (platform-scoped, threshold-applied) "
          f"- {detected_all}/{total_all} techniques detectable ({overall:.1f}%):")
    print(f"  {'tactic':<22}{'total':>6}{'detect':>8}  {'pct':>6}  bar")
    for row in rows:
        print(f"  {row.tactic:<22}{row.total:>6}{row.detectable:>8}  "
              f"{row.pct:>5.1f}%  {render_bar(row.pct)}")
    print()


def print_gaps(gaps: Sequence[Any], top: int) -> None:
    """Print gap totals, closable-by aggregation and the top-N gap rows."""
    if not gaps:
        print("Gaps: none - every scoped technique meets the threshold.")
        return
    print(f"Gaps (undetected techniques): {len(gaps)}")
    closers: dict[str, int] = {}
    for gap in gaps:
        for fmt in gap.closable_by:
            closers[fmt] = closers.get(fmt, 0) + 1
    if closers:
        hints = ", ".join(f"'{fmt}' closes {n}" for fmt, n in sorted(closers.items()))
        print(f"  enabling currently-disabled sources would help: {hints}")
    shown = gaps[:max(0, top)]
    if shown:
        print(f"  lowest-confidence {len(shown)}:")
        for gap in shown:
            closable = (f"  closable_by={','.join(gap.closable_by)}"
                        if gap.closable_by else "")
            print(f"    [{gap.tactic}] {gap.technique_attack_id} {gap.name}"
                  f" (best {gap.best_confidence:.2f}){closable}")
    print()


def build_gap_items(gaps: Sequence[Any],
                    descriptions: dict[str, str]) -> list[Any]:
    """Map engine Gaps to clustering GapItems, attaching technique descriptions.

    Args:
        gaps: ``Gap`` frozen dataclasses from ``calculate_coverage_gaps``.
        descriptions: attack_id -> description lookup built from the
            techniques table (the Gap shape intentionally omits it).

    Returns:
        List of ``gap_clustering.GapItem(technique_attack_id, name, tactic,
        description)`` ready for ``cluster_gaps``.
    """
    gap_clustering = sys.modules.get("analysis.gap_clustering")
    if gap_clustering is None:  # pragma: no cover - defensive
        raise ImportError("analysis.gap_clustering not imported")
    item_cls = _require(gap_clustering, "GapItem", "analysis.gap_clustering")
    items = [
        item_cls(
            technique_attack_id=gap.technique_attack_id,
            name=gap.name,
            tactic=gap.tactic,
            description=descriptions.get(gap.technique_attack_id, ""),
        )
        for gap in gaps
    ]
    logger.debug("built %d GapItems for clustering", len(items))
    return items


def print_clusters(clusters: Iterable[Any]) -> None:
    """Print KMeans gap clusters (or the single-cluster conservative fallback)."""
    clusters = list(clusters)
    if not clusters:
        print("Clusters: none.")
        return
    print(f"Gap clusters: {len(clusters)}")
    for cluster in clusters:
        members = ", ".join(cluster.technique_ids)
        print(f"  [{cluster.cluster_id}] {cluster.label} (size={cluster.size})")
        print(f"      members: {members}")
        print(f"      {cluster.summary}")
    print()


# --------------------------------------------------------------------------
# Pipeline
# --------------------------------------------------------------------------

def load_descriptions(session: Any) -> dict[str, str]:
    """Return attack_id -> description for every technique in the DB.

    Duplicate attack_ids (revoked/deprecated generations) collapse to one
    arbitrary description; descriptions are display-only clustering input.
    """
    rows = session.query(Technique.attack_id, Technique.description).all()
    return {attack_id: description or "" for attack_id, description in rows}


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


def run_report(args: argparse.Namespace) -> int:
    """Execute the demo pipeline; return the process exit code."""
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

    api = import_coverage_engine()

    with session_scope(engine) as session:
        meta = session.query(AttackMeta).order_by(AttackMeta.id.desc()).first()
        print_provenance(meta, url)

        if not ensure_techniques(session, allow_load=args.load):
            logger.error(
                "techniques table is empty at %s; run the Phase-1 loader "
                "first or re-run this script with --load", url,
            )
            return EXIT_EMPTY_DB

        rules = load_mappings(str(args.mappings))

        if args.skip_populate:
            logger.info("skipping technique_coverage population (--skip-populate)")
        else:
            report = api["populate_technique_coverage"](session, rules, config)
            print_populate_summary(report)

        rows = api["load_coverage_rows"](session, config)
        tactics = api["coverage_by_tactic"](rows)
        print_tactic_table(tactics)

        gaps = api["calculate_coverage_gaps"](rows, rules, config)
        print_gaps(gaps, top=args.top)

        if gaps:
            items = build_gap_items(gaps, load_descriptions(session))
            clusters = api["cluster_gaps"](items, config)
            print_clusters(clusters)
        else:
            print("Clusters: none needed - no gaps to group.")
    return 0


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser (kept separate for testability)."""
    parser = argparse.ArgumentParser(
        prog="run_coverage_report.py",
        description="Phase 3 demo: populate technique coverage, print "
                    "per-tactic detectability, gaps and gap clusters.",
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
    parser.add_argument("--top", type=int, default=10,
                        help="how many lowest-confidence gaps to list (default: 10)")
    parser.add_argument("--skip-populate", action="store_true",
                        help="report from existing technique_coverage rows only")
    parser.add_argument("--load", action="store_true",
                        help="when the techniques table is empty, load ATT&CK "
                             "from the local STIX cache first")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="INFO-level diagnostics on stderr")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point: configure logging, run the pipeline, map known failures.

    Engine-module absence becomes exit code 3 with a precise message;
    every other loader/parser/engine exception propagates untouched.
    """
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )
    try:
        return run_report(args)
    except ImportError as exc:
        # Only reachable for engine-side import problems; config/db imports
        # above are hard dependencies and would have failed earlier.
        logger.error("%s", exc)
        return EXIT_MISSING_ENGINE


if __name__ == "__main__":
    raise SystemExit(main())
