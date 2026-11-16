"""Streamlit Coverage Overview view (Phase 6).

Renders the 14-bucket tactic coverage rollup from
:func:`analysis.coverage_analyzer.coverage_by_tactic` as a Plotly heatmap plus
summary KPIs.  Adds an Estimated Addressable panel showing per-source marginal
contribution.  Pure renderer: it reads coverage rows and never mutates the DB.

Frozen contract: PLAN.md §5 Phase 6 view 1 -- Coverage Overview (Plotly tactic
heatmap + Estimated Addressable panel).
"""

from __future__ import annotations

from typing import Any

import plotly.graph_objects as go
import streamlit as st

from src.analysis.coverage_analyzer import (
    coverage_by_tactic,
    load_coverage_rows,
)
from src.visualization.views.styles import inject_css  # noqa: F401

# Cividis colorscale (swarm2 resolved architecture) sampled at a few stops.
# Perceptually uniform, colorblind-safe.
_CIVIDIS = [
    [0.0, "#0f172a"],
    [0.25, "#1e3a5c"],
    [0.5, "#3b82f6"],
    [0.75, "#3b82f6"],
    [1.0, "#60a5fa"],
]


def _kpi_cards(rows: list[Any], config: dict[str, Any]) -> None:
    """Render the summary KPI row derived from *rows*.

    KPIs: in-scope techniques, detectable, overall coverage %, platform scope,
    confidence threshold.  All computed from the data -- no hardcoded numbers.
    """
    in_scope = [r for r in rows if r.scope_hit]
    detectable = [r for r in in_scope if r.is_detectable]
    total = len(in_scope)
    det = len(detectable)
    pct = round(det / total, 4) if total else 0.0

    scope = config.get("platform_scope", "all")
    threshold = config.get("detection_confidence_threshold", 0.6)

    cols = st.columns(5)
    cols[0].metric("In-scope techniques", total)
    cols[1].metric("Detectable", det)
    cols[2].metric("Coverage %", f"{pct * 100:.2f}%")
    cols[3].metric("Platform scope", scope)
    cols[4].metric("Threshold", f"{threshold}")


def _heatmap(tactic_coverage: tuple[Any, ...]) -> go.Figure:
    """Build the tactic-coverage heatmap.

    Args:
        tactic_coverage: 14 TacticCoverage entries in canonical order.

    Returns:
        A Plotly Figure ready for ``st.plotly_chart``.
    """
    tactics = [tc.tactic for tc in tactic_coverage]
    pcts = [tc.pct for tc in tactic_coverage]
    hovers = [
        f"{tc.tactic}: {tc.detectable}/{tc.total} ({tc.pct * 100:.1f}%)"
        for tc in tactic_coverage
    ]

    tactics = list(reversed(tactics))
    pcts = list(reversed(pcts))
    hovers = list(reversed(hovers))

    fig = go.Figure(
        go.Heatmap(
            z=[pcts],
            x=["Coverage %"],
            y=tactics,
            zmin=0.0,
            zmax=1.0,
            colorscale=_CIVIDIS,
            text=[hovers],
            hoverinfo="text",
            showscale=True,
            colorbar=dict(title="Coverage", tickformat=".0%"),
        )
    )
    fig.update_layout(
        height=max(300, 24 * len(tactics) + 80),
        margin=dict(l=120, r=40, t=20, b=40),
        xaxis=dict(visible=False),
    )
    return fig


def _estimated_addressable_panel(
    rows: list[Any],
    config: dict[str, Any],
) -> None:
    """Render the Estimated Addressable panel.

    Calculates per-source estimated addressable techniques against the current
    missed gaps. Each source measured independently against the current missed
    gaps. Gains may overlap; do not sum them.
    """
    from src.analysis.coverage_analyzer import (
        build_closable_index,
        calculate_coverage_gaps,
    )
    from src.parser.mappings_io import load_mappings

    with st.spinner("Computing source contributions..."):
        rules = load_mappings("data/attack_mappings.csv")
        gaps = calculate_coverage_gaps(rows, rules, config)
        closable_index = build_closable_index(rules, config)

    enabled_sources = frozenset(
        s for s, v in config.get("enabled_log_sources", {}).items() if v
    )

    # Collect all disabled sources that appear in closable_index
    all_closable_sources = set()
    for srcs in closable_index.values():
        all_closable_sources.update(srcs)

    disabled_sources = sorted(
        all_closable_sources - frozenset(
            config.get("enabled_log_sources", {}).keys()
        )
    )

    if not disabled_sources:
        st.info(
            "No disabled sources with threshold-reaching mappings found."
        )
        return

    # Build technique set for current gaps
    gap_techniques = {
        g.technique_attack_id
        for g in rows
        if not g.is_detectable and g.scope_hit
    }

    st.subheader(
        "Estimated Addressable Techniques "
        "(Independent vs Baseline)"
    )
    st.caption(
        "Each disabled source's estimated addressable techniques, measured "
        "independently against the current missed gaps. Gains may overlap; "
        "do not sum them. For sequential marginal gains, see APT Simulation "
        "→ Recommendations."
    )

    for src in sorted(disabled_sources):
        addressable = {
            g.technique_attack_id
            for g in rows
            if not g.is_detectable and g.scope_hit
            and src in (g.closable_by if hasattr(g, "closable_by") else ())
        }
        if src in closable_index:
            technique_ids = closable_index.get(src, ())
            addressable.update(
                tid for tid in technique_ids if tid in gap_techniques
            )

        if addressable:
            st.markdown(f"**{src}**: {len(addressable)} techniques")
            with st.expander(f"Techniques addressable by {src}"):
                for tid in sorted(addressable):
                    st.markdown(f"- {tid}")
        else:
            st.markdown(f"**{src}**: 0 techniques")

    st.caption(
        "Each source measured independently against the current baseline. "
        "Gains may overlap -- do not sum. "
        "For sequential marginal-gain ranking, see APT Simulation → "
        "Recommendations."
    )


def render_coverage_view(session: Any, config: dict[str, Any]) -> None:
    """Render the Coverage Overview dashboard.

    Reads coverage rows for *config*, aggregates by tactic, and renders KPI
    cards + the Cividis heatmap.  Empty/zero states render an info banner
    instead of raising.

    Args:
        session: An open SQLAlchemy session.
        config: The live config mapping (source of truth for enablement).
    """
    inject_css()

    st.header("Coverage Overview")
    st.caption(
        "Detectability of in-scope ATT&CK techniques, rolled up across the 14 "
        "canonical Enterprise tactics.  Toggle log sources in the sidebar to "
        "see coverage respond."
    )

    with st.spinner("Computing coverage..."):
        rows = list(load_coverage_rows(session, config))

    if not rows:
        st.info("No techniques loaded.  Run the ATT&CK ingest first.")
        return

    # --- KPI row ---
    _kpi_cards(rows, config)

    st.markdown("---")
    st.markdown('<div class="section-title">Coverage by tactic</div>', unsafe_allow_html=True)
    tactic_coverage = coverage_by_tactic(rows)
    st.plotly_chart(_heatmap(tactic_coverage), use_container_width=True)

    with st.expander("Tactic detail", expanded=False):
        st.dataframe(
            [
                {
                    "tactic": tc.tactic,
                    "detectable": tc.detectable,
                    "total": tc.total,
                    "coverage": f"{tc.pct * 100:.1f}%",
                }
                for tc in tactic_coverage
            ],
            use_container_width=True,
            hide_index=True,
        )

    st.markdown("---")

    # --- Estimated addressable panel ---
    _estimated_addressable_panel(rows, config)