"""Phase 5 hunt-query demo: emit queries for a simulation run and print them.

Runs the full dispatch pipeline (:func:`detections.hunt_query_generator.export_all_queries`)
over a committed simulation result and prints every emitted query with its
attribution badge, demonstrating all three precedence tiers:

1. **hand-curated** (M001-M020 core set)
2. **community-sourced** (SigmaHQ rule converted via pySigma)
3. **generic** (``# UNREVIEWED`` fallback template)

Usage:

    ./.venv/Scripts/python.exe scripts/run_hunt_demo.py            # default G0016
    ./.venv/Scripts/python.exe scripts/run_hunt_demo.py G0096      # another group
    ./.venv/Scripts/python.exe scripts/run_hunt_demo.py G0016 --sigma-dir data/sigma

The script is read-only on the committed ``db/coverage.db``: it opens a
transaction but rolls back the Phase-5 persistence so the demo can be re-run
safely.  (The conversion cache at ``data/cache/sigma_conversions.json`` IS
updated -- that is the intended side effect.)
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
# The detections module uses `from src...` imports, so the repo root (parent
# of src/) must be on sys.path to resolve the `src` package.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy import select  # noqa: E402

from database.session import make_engine, session_scope  # noqa: E402
from database.models import SimulationResult  # noqa: E402
from detections.hunt_query_generator import export_all_queries  # noqa: E402

logger = logging.getLogger(__name__)


def _resolve_result_id(session, group_id: str) -> int:
    """Find the most recent simulation result for a group."""
    row = (
        session.execute(
            select(SimulationResult)
            .where(SimulationResult.group_id == group_id)
            .order_by(SimulationResult.id.desc())
        )
        .scalars()
        .first()
    )
    if row is None:
        raise ValueError(
            f"no simulation result for {group_id} — "
            "run scripts/run_simulation_demo.py first"
        )
    return row.id


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "group_id",
        nargs="?",
        default="G0016",
        help="ATT&CK group id to demo (default: G0016).",
    )
    parser.add_argument(
        "--sigma-dir",
        default=None,
        help="Root of a SigmaHQ clone (enables the community-sourced tier).",
    )
    parser.add_argument(
        "--database-url",
        default=None,
        help="SQLAlchemy database URL (default: sqlite:///db/coverage.db).",
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
    with session_scope(engine) as session:
        result_id = _resolve_result_id(session, args.group_id)
        result = session.get(SimulationResult, result_id)
        print(
            f"# Group {result.group_id}: {result.total_techniques} techniques, "
            f"{result.detected_count} detected, {result.missed_count} missed, "
            f"{result.coverage_pct:.2%} coverage"
        )
        print(f"# Emitting hunt queries for result_id={result_id} ...\n")

        # Run the dispatch pipeline.  We pass the session so we can roll back
        # the Phase-5 persistence afterward (demo must be re-runnable).
        queries = export_all_queries(
            result_id,
            session=session,
            sigma_rules_dir=args.sigma_dir,
        )

        # Roll back the technique_coverage writes so the demo is idempotent;
        # the conversion cache (data/cache/sigma_conversions.json) is kept.
        session.rollback()

        if not queries:
            print("# No missed techniques — nothing to emit.")
            return 0

        # Summary by attribution label.
        breakdown = Counter(q["attribution_label"] for q in queries.values())
        print(
            f"# Emitted {len(queries)} queries: "
            + ", ".join(f"{k}={v}" for k, v in sorted(breakdown.items()))
            + "\n"
        )

        # Print each query with its badge.
        for tid, q in queries.items():
            badge = q["attribution_label"]
            lang = q["query_language"]
            conf = q["confidence"]
            print(f"-- {tid}  [{badge}]  conf={conf:.4f}  lang={lang} --")
            print(q["query"])
            if q["attribution_label"] == "community-sourced":
                attr = q.get("attribution", {})
                author = attr.get("author", "?")
                print(f"   # author: {author}")
                print(f"   # source: {attr.get('rule_url', '?')}")
            print()

        # Print a compact JSON summary (the export_all_queries contract).
        print("# --- JSON export (first 3 entries) ---")
        preview = dict(list(queries.items())[:3])
        print(json.dumps(preview, indent=2)[:800] + "\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
