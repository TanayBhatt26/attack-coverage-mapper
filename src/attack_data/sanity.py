"""Row-count sanity checker for the loaded ATT&CK database.

Loose ranges only - MITRE updates the framework periodically, so exact
numbers are never hardcoded (blueprint section 12, Phase 1).

Usage:  PYTHONPATH=src python -m attack_data.sanity [--db sqlite:///db/coverage.db]
"""
import argparse
import sys

from sqlalchemy import func, inspect as sa_inspect, MetaData, Table, select

from database.session import make_engine

# (min, max) per table; None = table must be absent or empty-tolerant.
RANGES = {
    "techniques": (800, 950),
    "detection_strategies": (600, 800),
    "analytics": (1500, 2000),
    "apt_groups": (175, 250),
    "apt_technique": (1000, 5000),
}


def check_counts(engine) -> list[tuple[str, int | None, bool]]:
    results = []
    inspector = sa_inspect(engine)
    existing = set(inspector.get_table_names())
    for table, (lo, hi) in RANGES.items():
        if table not in existing:
            results.append((table, None, False))
            continue
        # Table names come from the hardcoded RANGES dict, not user input.
        # Use SQLAlchemy Core for safety and portability.
        from sqlalchemy import func, MetaData, Table
        metadata = MetaData()
        n = engine.connect().execute(
            select(func.count()).select_from(Table(table, metadata, autoload_with=engine))
        ).scalar()
        results.append((table, n, lo <= n <= hi))
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default=None, help="Database URL override")
    args = parser.parse_args()

    engine = make_engine(args.db)
    rows = check_counts(engine)
    ok = True
    print(f"{'table':22s} {'count':>7s}  range        verdict")
    for table, n, passed in rows:
        lo, hi = RANGES[table]
        rng = f"{lo}-{hi}"
        verdict = "OK" if passed else "FAIL"
        ok &= passed
        print(f"{table:22s} {str(n):>7s}  {rng:12s} {verdict}")
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
