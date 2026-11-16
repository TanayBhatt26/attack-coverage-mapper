#!/usr/bin/env python
"""Coverage validation report generator.

Calculates and verifies the ATT&CK coverage numbers against the database.
Produces a timestamped report suitable for release documentation and viva preparation.

Run from repo root: PYTHONPATH=src ./.venv/Scripts/python.exe scripts/validate_coverage.py
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter

# Ensure src is on path when run as script
REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = REPO_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from sqlalchemy import select
from database.session import session_scope
from database.models import Technique
from config_loader import load_config
from analysis.coverage_analyzer import load_coverage_rows, calculate_coverage_gaps
from parser.mappings_io import load_mappings


def generate_report() -> dict:
    """Generate the complete validation report as a dict."""
    with session_scope() as session:
        config = load_config("config.yaml")
        rules = load_mappings("data/attack_mappings.csv")
        rows = list(load_coverage_rows(session, config))

        # Basic counts
        total_tech = session.query(Technique).count()
        alive_tech = session.query(Technique).filter(Technique.revoked == False).count()
        revoked = session.query(Technique).filter(Technique.revoked == True).count()

        # In-scope and detectable
        in_scope = [r for r in rows if r.scope_hit]
        detectable = [r for r in rows if r.scope_hit and r.is_detectable]

        # Mappings
        rules_list = load_mappings("data/attack_mappings.csv")
        mapping_tech_ids = {r.technique_id for r in rules_list}
        db_tech_ids = {r.attack_id for r in session.execute(
            select(Technique.attack_id).where(Technique.revoked == False)
        ).all()}
        unknown_in_mappings = mapping_tech_ids - {r.attack_id for r in session.execute(
            select(Technique.attack_id).where(Technique.revoked == False)
        ).all()}

        # Gaps
        gaps = list(calculate_coverage_gaps(rows, load_mappings("data/attack_mappings.csv"), load_config("config.yaml")))
        gaps_with_closable = [g for g in gaps if g.closable_by]
        gaps_no_closable = [g for g in gaps if not g.closable_by]

        # Per-tactic breakdown
        tactic_counts = Counter(g.tactic for g in gaps)

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "database": {
                "total_techniques": total_tech,
                "alive": alive_tech,
                "revoked": revoked,
            },
            "coverage": {
                "in_scope": len(in_scope),
                "detectable": len(detectable),
                "coverage_pct": round(len(detectable) / max(1, len(in_scope)) * 100, 2),
            },
            "mappings": {
                "total_rules": len(load_mappings("data/attack_mappings.csv")),
                "unique_techniques": len({r.technique_id for r in load_mappings("data/attack_mappings.csv")}),
                "unknown_technique_ids": len(unknown_in_mappings),
            },
            "gaps": {
                "total": len(gaps),
                "with_closable_source": len(gaps_with_closable),
                "without_closable_source": len(gaps_no_closable),
            },
            "gaps_by_tactic": dict(sorted(Counter(g.tactic for g in gaps).items())),
        }


def main() -> int:
    report = generate_report()
    # Print human-readable report
    print("=" * 60)
    print("ATT&CK COVERAGE VALIDATION REPORT")
    print("=" * 60)
    print(f"Generated: {report['timestamp']}")
    print()
    print("DATABASE")
    print(f"  Total techniques: {report['database']['total_techniques']}")
    print(f"  Alive (non-revoked): {report['database']['alive']}")
    print(f"  Revoked: {report['database']['revoked']}")
    print()
    print("COVERAGE")
    print(f"  In-scope techniques: {report['coverage']['in_scope']}")
    print(f"  Detectable (>=0.6): {report['coverage']['detectable']}")
    print(f"  Coverage: {report['coverage']['coverage_pct']:.2f}%")
    print()
    print("MAPPINGS")
    print(f"  Total rules: {report['mappings']['total_rules']}")
    print(f"  Unique techniques: {report['mappings']['unique_techniques']}")
    print(f"  Unknown technique IDs in mappings: {report['mappings']['unknown_technique_ids']}")
    print()
    print("GAPS")
    print(f"  Total gaps: {report['gaps']['total']}")
    print(f"  With closable source: {report['gaps']['with_closable_source']}")
    print(f"  Without closable source: {report['gaps']['without_closable_source']}")
    print()

    print("GAPS BY TACTIC")
    for tactic, count in report["gaps_by_tactic"].items():
        print(f"  {tactic}: {count}")
    print()

    # Save JSON report
    output_path = Path("validation_report.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"JSON report saved to {output_path}")

    return 0


if __name__ == "__main__":
    import sys
    import json
    from datetime import datetime, timezone
    from pathlib import Path
    from sqlalchemy import select
    from database.session import session_scope
    from database.models import Technique
    from config_loader import load_config
    from analysis.coverage_analyzer import load_coverage_rows, calculate_coverage_gaps
    from parser.mappings_io import load_mappings
    from collections import Counter

    sys.exit(main())