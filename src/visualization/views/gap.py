"""Streamlit Gap Analysis view (Phase 7).

Renders coverage gaps with evidence-based remediation bundles as the primary
analytical view, KMeans clusters as exploratory, and a full gap table.

Frozen contract: PLAN.md §5 Phase 6 view 4 -- Gap Analysis (remediation bundles
+ tactic groups + exploratory KMeans + full gap table).
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from sqlalchemy import select
import streamlit as st

from src.analysis.coverage_analyzer import (
    calculate_coverage_gaps,
    load_coverage_rows,
    _mapping_sources_for,
)
from src.analysis.gap_clustering import (
    ClusteringParams,
    GapCluster,
    GapItem,
    cluster_gaps,
)
from src.analysis.remediation import (
    RemediationCategory,
    classify_all_gaps,
)
from src.database.models import Technique
from src.parser.mappings_io import DEFAULT_MAPPINGS_PATH, load_mappings
from src.visualization.views.styles import inject_css  # noqa: F401

__all__ = ("render_gap_view",)


def _gap_items(
    gaps: tuple[Any, ...],
    session: Any,
) -> tuple[GapItem, ...]:
    """Build :class:`GapItem` inputs for clustering from raw :class:`Gap` rows."""
    ids = [g.technique_attack_id for g in gaps]
    desc_map: dict[str, str] = {}
    if ids:
        rows = session.execute(
            select(Technique.attack_id, Technique.description).where(
                Technique.attack_id.in_(ids)
            )
        ).all()
        desc_map = {
            aid: desc or "" for aid, desc in rows
        }

    return tuple(
        GapItem(
            technique_attack_id=g.technique_attack_id,
            name=g.name,
            tactic=g.tactic,
            description=desc_map.get(g.technique_attack_id, ""),
        )
        for g in gaps
    )


def _render_cluster(cluster: Any) -> None:
    """Render one labelled KMeans cluster as an expander (exploratory)."""
    import html
    label_safe = html.escape(str(cluster.label))
    summary_safe = html.escape(str(cluster.summary))
    technique_ids_safe = ", ".join(html.escape(str(t)) for t in cluster.technique_ids)

    with st.expander(
        f"Cluster {cluster.cluster_id}: {label_safe} "
        f"({cluster.size} techniques)",
        expanded=False,
    ):
        st.markdown(f"**Summary:** {summary_safe}")
        st.markdown("**Techniques:** " + technique_ids_safe)
        st.caption(
            "Exploratory: clusters by textual similarity of technique descriptions. "
            "Shared description words do not guarantee shared remediation. "
            "Compare with Remediation Bundles tab above."
        )


def _render_remediation_bundle(
    bundle_name: str,
    details: list[Any],
) -> None:
    """Render one remediation bundle as an expander with candidate details."""
    with st.expander(
        f"{bundle_name} ({len(details)} techniques)",
        expanded=False,
    ):
        for d in details:
            gap = d.gap
            st.markdown(f"### {gap.technique_attack_id}: {gap.name} ({gap.tactic})")

            # Candidate sources
            if d.candidate_sources:
                st.markdown("**Candidate sources:**")
                for c in d.candidate_sources:
                    status_badge = {
                        "collected_disabled": "🟢 Collected — disabled",
                        "not_collected": "🔴 Not collected",
                        "unknown_status": "⚪ Status unknown",
                        "validation_error": "🚨 Validation error",
                    }.get(c.status, c.status)
                    action_icon = {
                        "enable": "▶️ Enable",
                        "acquire": "💰 Acquire",
                        "investigate_status": "🔍 Investigate status",
                        "investigate": "🔍 Investigate",
                    }.get(c.action, c.action)
                    st.markdown(
                        f"- `{c.source}` — {status_badge} → {action_icon}"
                    )

            # Enabled source evidence
            if d.enabled_source_evidence:
                st.markdown(
                    f"**Enabled source evidence:** source_ids={d.enabled_source_evidence}"
                )

            # Mapping sources
            if d.enabled_mapping_sources:
                st.markdown(
                    f"**Mappings in enabled sources:** {', '.join(d.enabled_mapping_sources)}"
                )
            if d.all_mapping_sources:
                st.markdown(
                    f"**All known mapping sources:** {', '.join(d.all_mapping_sources)}"
                )

            st.markdown("---")


def _render_unresolved_section(details: list[Any]) -> None:
    """Render the unresolved gaps section (empty closable_by)."""
    st.subheader(f"Unresolved gaps ({len(details)})")
    st.caption(
        "These gaps have no candidate source whose static projection reaches the "
        "threshold. Remediation depends on mapping/telemetry review."
    )

    # Group by primary category
    by_category = defaultdict(list)
    for d in details:
        by_category[d.primary_category].append(d)

    for category in [
        RemediationCategory.REVIEW_EXISTING_SOURCE_MAPPINGS,
        RemediationCategory.MAPPING_TELEMETRY_REVIEW,
        RemediationCategory.MAPPING_COVERAGE_GAP,
        RemediationCategory.DATA_QUALITY_ISSUE,
    ]:
        items = by_category.get(category)
        if not items:
            continue
        with st.expander(f"{category.value} ({len(items)})", expanded=False):
            for d in items:
                gap = d.gap
                st.markdown(f"### {gap.technique_attack_id}: {gap.name} ({gap.tactic})")
                st.markdown(f"**Best confidence:** {gap.best_confidence:.4f}")
                if d.enabled_source_evidence:
                    st.markdown(
                        f"**Enabled source evidence (source_ids):** {d.enabled_source_evidence}"
                    )
                if d.enabled_mapping_sources:
                    st.markdown(
                        f"**Mappings in enabled sources:** {', '.join(d.enabled_mapping_sources)}"
                    )
                if d.all_mapping_sources:
                    st.markdown(
                        f"**All known mapping sources:** {', '.join(d.all_mapping_sources)}"
                    )
                if d.validation_errors:
                    st.error(
                        "Validation errors: " + "; ".join(d.validation_errors)
                    )
                st.markdown("---")


def render_gap_view(session: Any, config: dict[str, Any]) -> None:
    """Render the Gap Analysis dashboard with Remediation Bundles as primary view."""
    inject_css()
    st.header("Gap Analysis")
    st.caption(
        "Undetected in-scope techniques, grouped by evidence-based remediation "
        "actions. Toggle log sources in the sidebar to watch bundles shift."
    )

    with st.spinner("Analyzing gaps..."):
        rows = list(load_coverage_rows(session, config))
        rules = load_mappings(DEFAULT_MAPPINGS_PATH)
        gaps = calculate_coverage_gaps(rows, rules, config)

    if not gaps:
        st.info("No coverage gaps -- every in-scope technique is detectable.")
        return

    # Classify all gaps for remediation
    enabled_sources = frozenset(
        s for s, v in config.get("enabled_log_sources", {}).items() if v
    )
    collected_sources = config.get("collected_log_sources")
    threshold = config.get("detection_confidence_threshold", 0.6)
    all_rules_by_source = {}
    for rule in rules:
        all_rules_by_source.setdefault(rule.source_format, []).append(rule)

    from src.analysis.remediation import classify_all_gaps
    remediation_details = classify_all_gaps(
        gaps=gaps,
        coverage_rows=rows,
        enabled_sources=enabled_sources,
        collected_sources=config.get("collected_log_sources"),
        all_rules_by_source=all_rules_by_source,
        threshold=threshold,
    )

    # Key KPIs
    cols = st.columns(4)
    cols[0].metric("Total gaps", len(gaps))
    with_closable = [d for d in remediation_details if d.candidate_sources]
    cols[1].metric("Gaps with candidate source", len(with_closable))
    without_closable = [d for d in remediation_details if not d.candidate_sources]
    cols[2].metric("Unresolved gaps", len(without_closable))
    validation_issues = [d for d in remediation_details if d.validation_errors]
    cols[3].metric("Data quality issues", len(validation_issues))

    st.markdown("---")

    # Tabs: primary = Remediation Bundles, secondary = Tactic Groups, exploratory = KMeans
    tab_bundles, tab_tactic, tab_kmeans, tab_all = st.tabs([
        "🎯 Remediation Bundles",
        "📋 Tactic Groups",
        "🔬 Exploratory KMeans",
        "📊 All Gaps",
    ])

    with tab_bundles:
        st.markdown('<div class="section-title">Remediation Bundles</div>', unsafe_allow_html=True)
        st.caption(
            "Gaps grouped by shared candidate-source signature. "
            "Each bundle represents a potential coordinated remediation action."
        )

        # Group by exact non-empty candidate-source signature
        bundles = defaultdict(list)
        unresolved = []
        for d in remediation_details:
            if d.candidate_sources:
                sig = tuple(sorted(
                    (c.source, c.status) for c in d.candidate_sources
                ))
                bundles[sig].append(d)
            else:
                unresolved.append(d)

        # Sort bundles by size (largest first)
        for sig, items in sorted(bundles.items(), key=lambda x: -len(x[1])):
            source_names = ", ".join(s for s, _ in sig)
            statuses = ", ".join(f"{s}({st})" for s, st in sig)
            bundle_name = f"Bundle: {source_names} — [{statuses}]"
            _render_remediation_bundle(bundle_name, items)

        if unresolved:
            _render_unresolved_section(unresolved)

    with tab_tactic:
        st.markdown('<div class="section-title">Tactic Groups</div>', unsafe_allow_html=True)
        st.caption("Traditional ATT&CK tactic grouping for reference.")
        by_tactic = defaultdict(list)
        for g in gaps:
            by_tactic[g.tactic].append(g)

        for tactic in sorted(by_tactic.keys()):
            items = by_tactic[tactic]
            with st.expander(f"{tactic} ({len(items)})", expanded=False):
                st.dataframe(
                    [
                        {
                            "technique": g.technique_attack_id,
                            "name": g.name,
                            "confidence": f"{g.best_confidence:.4f}",
                            "closable_by": ", ".join(g.closable_by) or "—",
                        }
                        for g in items
                    ],
                    use_container_width=True,
                    hide_index=True,
                )

    with tab_kmeans:
        st.markdown('<div class="section-title">Exploratory KMeans Clusters</div>', unsafe_allow_html=True)
        st.caption(
            "Clusters by textual similarity of technique descriptions. "
            "Shared description words do not guarantee shared remediation. "
            "Compare with Remediation Bundles tab above."
        )
        params = ClusteringParams.from_config(config.get("clustering"))
        from src.analysis.gap_clustering import GapItem
        items = []
        ids = [g.technique_attack_id for g in gaps]
        desc_map = {}
        if ids:
            rows = session.execute(
                select(Technique.attack_id, Technique.description).where(
                    Technique.attack_id.in_(ids)
                )
            ).all()
            desc_map = {aid: desc or "" for aid, desc in rows}
        for g in gaps:
            from src.analysis.gap_clustering import GapItem
            items.append(GapItem(
                technique_attack_id=g.technique_attack_id,
                name=g.name,
                tactic=g.tactic,
                description=desc_map.get(g.technique_attack_id, ""),
            ))
        clusters = cluster_gaps(items, params)
        for cluster in clusters:
            _render_cluster(cluster)

    with tab_all:
        st.markdown('<div class="section-title">All Gaps (Full Detail)</div>', unsafe_allow_html=True)
        st.dataframe(
            [
                {
                    "technique": g.technique_attack_id,
                    "name": g.name,
                    "tactic": g.tactic,
                    "confidence": f"{g.best_confidence:.4f}",
                    "closable_by": ", ".join(g.closable_by) or "—",
                    "remediation": d.primary_category.value,
                }
                for g, d in zip(gaps, remediation_details)
            ],
            use_container_width=True,
            hide_index=True,
        )