"""Phase 7 comprehensive demo: coverage overview, APT simulation, hunt queries, gap analysis.

Demonstrates the full Phase 7 analytical workflow:
1. Coverage Overview — 14-tactic heatmap + Estimated Addressable panel
2. APT Simulation — group picker, KPIs, per-tactic bars, recommendations
3. Hunt Queries — gap list + per-technique queries with remediation links
4. Gap Analysis — Remediation Bundles (primary) + Tactic Groups + KMeans (exploratory)

Usage:
    ./.venv/Scripts/python.exe scripts/run_phase7_demo.py           # default G0016
    ./.venv/Scripts/python.exe scripts/run_phase7_demo.py G0096    # another group
    ./.venv/Scripts/python.exe scripts/run_phase7_demo.py G0016 --sigma-dir data/sigma
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy import select  # noqa: E402

from database.session import make_engine, session_scope  # noqa: E402
from database.models import SimulationResult  # noqa: E402

from analysis.coverage_analyzer import (
    load_coverage_rows,
    coverage_by_tactic,
    calculate_coverage_gaps,
    build_closable_index,
)  # noqa: E402
from analysis.simulation import (
    simulate_apt_attack,
    generate_recommendations,
    list_apt_groups,
)  # noqa: E402
from detections.hunt_query_generator import export_all_queries  # noqa: E402
from parser.mappings_io import load_mappings  # noqa: E402
from analysis.remediation import (
    classify_all_gaps,
    RemediationCategory,
)  # noqa: E402
from config_loader import load_config  # noqa: E402

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


def _print_coverage_overview(session, config) -> None:
    """Print Coverage Overview: KPIs + tactic heatmap + estimated addressable."""
    print("=" * 70)
    print("COVERAGE OVERVIEW")
    print("=" * 70)

    rows = list(load_coverage_rows(session, config))
    in_scope = [r for r in rows if r.scope_hit]
    detectable = [r for r in in_scope if r.is_detectable]
    total = len(in_scope)
    det = len(detectable)
    pct = round(det / total, 4) if total else 0.0

    print(f"In-scope techniques: {total}")
    print(f"Detectable: {det}")
    print(f"Coverage: {pct * 100:.2f}%")
    print(f"Platform scope: {config.get('platform_scope', 'all')}")
    print(f"Threshold: {config.get('detection_confidence_threshold', 0.6)}")

    # Tactic heatmap
    print("\n--- Tactic Coverage ---")
    tactic_cov = coverage_by_tactic(rows)
    for tc in tactic_cov:
        filled = int(tc.pct * 20)
        empty = 20 - filled
        bar = "#" * filled + "." * empty
        print(f"  {tc.tactic:>22}: {tc.detectable:>3}/{tc.total:<3} ({tc.pct*100:>5.1f}%) {bar}")

    # Estimated Addressable
    print("\n--- Estimated Addressable Techniques (Independent vs Baseline) ---")
    rules = load_mappings("data/attack_mappings.csv")
    from analysis.coverage_analyzer import calculate_coverage_gaps, build_closable_index
    gaps = calculate_coverage_gaps(rows, rules, config)
    closable_index = build_closable_index(rules, config)
    enabled_sources = frozenset(s for s, v in config.get("enabled_log_sources", {}).items() if v)
    all_closable = set().union(*closable_index.values())
    disabled_sources = sorted(all_closable - frozenset(config.get("enabled_log_sources", {}).keys()))
    gap_techniques = {g.attack_id for g in rows if not g.is_detectable and g.scope_hit}

    for src in disabled_sources:
        addressable = {
            g.technique_attack_id
            for g in rows
            if not g.is_detectable and g.scope_hit and src in getattr(g, 'closable_by', ())
        }
        if src in closable_index:
            addressable.update(tid for tid in closable_index.get(src, ()) if tid in gap_techniques)
        if addressable:
            print(f"  {src}: {len(addressable)} techniques")
            for tid in sorted(addressable)[:5]:
                print(f"    - {tid}")
            if len(addressable) > 5:
                print(f"    ... and {len(addressable) - 5} more")


def _print_apt_simulation(session, config, group_id: str) -> None:
    """Print APT Simulation: KPIs, per-tactic bars, recommendations."""
    print("\n" + "=" * 70)
    print(f"APT SIMULATION: {group_id}")
    print("=" * 70)

    result = simulate_apt_attack(group_id, session=session, config=config, persist=False)
    summary = result.summary
    print(f"Group: {group_id} ({result.group_id})")
    print(f"Total: {summary.get('counts', {}).get('total', 0)} | "
          f"Detected: {summary.get('counts', {}).get('detected', 0)} | "
          f"Rollup: {summary.get('counts', {}).get('detected_rollup', 0)} | "
          f"Missed: {summary.get('counts', {}).get('missed', 0)}")
    print(f"Coverage: {result.coverage_pct * 100:.2f}%")

    print("\n--- Per-Tactic Breakdown ---")
    per_tactic = summary.get("per_tactic", {})
    for tactic in sorted(per_tactic.keys()):
        tb = per_tactic[tactic]
        det = tb.get("detected", 0)
        miss = tb.get("missed", 0)
        total_t = tb.get("total", 0)
        det_filled = int(det / max(total_t, 1) * 20)
        miss_filled = int(tb.get("missed", 0) / max(total_t, 1) * 20)
        det_bar = "#" * det_filled
        miss_bar = "." * miss_filled
        print(f"  {tactic:>22}: {'#'*det_filled}{'.'*miss_filled}  det={det} miss={tb.get('missed', 0)}")

    print("\n--- Recommendations (Greedy Marginal Gain) ---")
    recs = generate_recommendations(result, session)
    for i, rec in enumerate(recs, 1):
        print(f"  {i}. {rec}")

    # Show missed techniques
    print(f"\n--- Missed Techniques ---")
    from database.models import SimulationTechnique
    missed = session.query(SimulationTechnique).filter(
        SimulationTechnique.result_id == result.id,
        SimulationTechnique.status == "missed"
    ).all()
    if missed:
        for t in missed[:10]:
            print(f"  {t.technique_attack_id:>12} {t.name:>30} [{t.tactic}] conf={t.confidence:.3f} src={t.contributing_sources or 'none'}")
        if len(missed) > 10:
            print(f"  ... and {len(missed) - 10} more")


def _print_hunt_queries(session, config, result_id: int, sigma_dir: str | None) -> None:
    """Print Hunt Queries: gap list + per-technique queries with remediation links."""
    print("\n" + "=" * 70)
    print("HUNT QUERIES")
    print("=" * 70)

    queries = export_all_queries(
        result_id,
        session=session,
        config=config,
        sigma_rules_dir=sigma_dir,
    )
    session.rollback()  # keep demo idempotent

    if not queries:
        print("# No missed techniques — nothing to emit.")
        return

    breakdown = Counter(q["attribution_label"] for q in queries.values())
    print(f"Emitted {len(queries)} queries: " + ", ".join(f"{k}={v}" for k, v in sorted(breakdown.items())))

    print("\n--- Gap List ---")
    for tid, q in queries.items():
        print(f"  {tid:>12} [{q['attribution_label']:>20}] conf={q['confidence']:.4f} closable={q['closable_by'] or 'none'}")

    print("\n--- Per-Technique Queries (first 5) ---")
    for tid, q in list(queries.items())[:5]:
        print(f"\n-- {tid} [{q['attribution_label']}] conf={q['confidence']:.4f} lang={q['query_language']} --")
        print(q["query"][:500] + ("..." if len(q["query"]) > 500 else ""))
        if q["attribution_label"] == "community-sourced":
            attr = q.get("attribution", {})
            print(f"   # author: {attr.get('author', '?')}")
            print(f"   # source: {attr.get('rule_url', '?')}")


def _print_gap_analysis(session, config) -> None:
    """Print Gap Analysis: Remediation Bundles + Unresolved."""
    print("\n" + "=" * 70)
    print("GAP ANALYSIS — REMEDIATION BUNDLES")
    print("=" * 70)

    rows = list(load_coverage_rows(session, config))
    rules = load_mappings("data/attack_mappings.csv")
    gaps = calculate_coverage_gaps(rows, rules, config)

    from analysis.remediation import classify_all_gaps
    enabled = frozenset(s for s, v in config.get("enabled_log_sources", {}).items() if v)
    collected = config.get("collected_log_sources")
    threshold = config.get("detection_confidence_threshold", 0.6)
    rules_by_source = {}
    for rule in load_mappings("data/attack_mappings.csv"):
        rules_by_source.setdefault(rule.source_format, []).append(rule)

    details = classify_all_gaps(
        gaps=gaps,
        coverage_rows=rows,
        enabled_sources=enabled,
        collected_sources=collected,
        all_rules_by_source=rules_by_source,
        threshold=config.get("detection_confidence_threshold", 0.6),
    )

    print(f"Total gaps: {len(gaps)}")
    with_closable = [d for d in details if d.candidate_sources]
    without = [d for d in details if not d.candidate_sources]
    validation = [d for d in details if d.validation_errors]
    print(f"  With candidate source: {len(with_closable)}")
    print(f"  Unresolved: {len(without)}")
    print(f"  Data quality issues: {len(validation)}")

    # Group by candidate signature
    from collections import defaultdict
    bundles = defaultdict(list)
    unresolved = []
    for d in details:
        if d.candidate_sources:
            sig = tuple(sorted((c.source, c.status) for c in d.candidate_sources))
            bundles[sig].append(d)
        else:
            unresolved.append(d)

    print("\n--- Remediation Bundles (by shared candidate signature) ---")
    for sig, items in sorted(bundles.items(), key=lambda x: -len(x[1])):
        source_names = ", ".join(s for s, _ in sig)
        statuses = ", ".join(f"{s}({st})" for s, st in sig)
        print(f"\n  Bundle: {source_names} — [{statuses}] ({len(items)} techniques)")
        for d in items[:3]:
            gap = d.gap
            cand_str = ", ".join(f"{c.source}({c.status})" for c in d.candidate_sources)
            print(f"  {gap.technique_attack_id:>12} {gap.name:>30} [{gap.tactic}] candidates={cand_str}")
        if len(items) > 3:
            print(f"  ... and {len(items) - 3} more")

    if unresolved:
        print(f"\n--- Unresolved ({len(unresolved)}) ---")
        by_cat = defaultdict(list)
        for d in unresolved:
            by_cat[d.primary_category].append(d)
        for cat in [
            RemediationCategory.REVIEW_EXISTING_SOURCE_MAPPINGS,
            RemediationCategory.MAPPING_TELEMETRY_REVIEW,
            RemediationCategory.MAPPING_COVERAGE_GAP,
        ]:
            items = [d for d in unresolved if d.primary_category == cat]
            if not items:
                continue
            print(f"\n  {cat.value} ({len(items)}):")
            for d in items[:5]:
                gap = d.gap
                if d.enabled_mapping_sources:
                    print(f"  {gap.technique_attack_id:>12} {gap.name:>30} mappings={d.enabled_mapping_sources}")
                elif d.all_mapping_sources:
                    print(f"  {gap.technique_attack_id:>12} {gap.name:>30} all_mappings={d.all_mapping_sources}")
                else:
                    print(f"  {gap.technique_attack_id:>12} {gap.name:>30} NO MAPPING")


def _resolve_result_id(session, group_id: str) -> int:
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
        "-v", "--verbose",
        action="store_true",
        help="Enable INFO-level logging.",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    config = load_config("config.yaml")
    engine = make_engine(args.database_url)

    with session_scope(engine) as session:
        result_id = _resolve_result_id(session, args.group_id)
        result = session.get(SimulationResult, result_id)

        print(f"\n# Group {result.group_id}: {result.total_techniques} techniques, "
              f"{result.detected_count} detected, {result.missed_count} missed, "
              f"{result.coverage_pct:.2%} coverage")
        print(f"# Result ID: {result_id}\n")

        _print_coverage_overview(session, config)
        _print_apt_simulation(session, config, args.group_id)
        _print_hunt_queries(session, config, result_id, args.sigma_dir)
        _print_gap_analysis(session, config)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())