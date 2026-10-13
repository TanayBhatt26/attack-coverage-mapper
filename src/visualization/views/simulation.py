"""Streamlit APT Simulation view (Phase 6).

Renders a group picker, runs :func:`analysis.simulation.simulate_apt_attack`,
and displays the frozen :class:`SimulationOutcome` -- KPI row, per-tactic
detected/missed bar chart, plain-language recommendations, and a missed-
technique detail table.

Pure renderer: it delegates all computation to the analysis layer and never
mutates the DB itself (``simulate_apt_attack`` owns persistence when
``persist=True``).

Frozen contract: PLAN.md §5 Phase 6 view 2 -- APT Simulation (detected/missed +
plain-language recommendations).
"""

from __future__ import annotations

from typing import Any

import plotly.graph_objects as go
import streamlit as st

from src.analysis.simulation import (
    list_apt_groups,
    simulate_apt_attack,
)
from src.database.session import session_scope

__all__ = ("render_simulation_view",)


def _group_picker(session: Any, config: dict[str, Any]) -> str:
    """Render the APT group selector; return the chosen ``group_id``.

    Uses the committed DB's group picker data.  Defaults to the most-impactful
    group (first in the picker's count-desc sort) so a first visit shows a
    meaningful simulation immediately.

    Args:
        session: An open SQLAlchemy session.
        config: The live config mapping.

    Returns:
        The selected ``group_id`` (e.g. ``"G0016"``).
    """
    options = list_apt_groups(session)
    if not options:
        st.warning("No APT groups loaded.  Run the ATT&CK ingest first.")
        st.stop()

    # Picker label: "<name/alias> (<count>)"; value: group_id (the lookup key).
    labels = [opt.label for opt in options]
    values = [opt.group_id for opt in options]
    default = values[0]

    return st.sidebar.selectbox(
        "APT group",
        options=values,
        index=0,
        format_func=lambda gid: labels[values.index(gid)],
        help="Select an APT group to simulate. Defaults to the most-impactful group.",
    ) or default


def _render_outcome(outcome: Any) -> None:
    """Render a completed :class:`SimulationOutcome`.

    KPI row, per-tactic detected/missed bar chart, recommendations, and a
    missed-technique detail table.

    Args:
        outcome: A :class:`SimulationOutcome` (frozen, hashable).
    """
    # --- KPI row ---
    st.subheader("Simulation results")
    cols = st.columns(5)
    cols[0].metric("Total techniques", outcome.total)
    cols[1].metric("Detected", outcome.detected)
    cols[2].metric("Detected (incl. rollup)", outcome.detected + outcome.detected_rollup)
    cols[3].metric("Missed", outcome.missed)
    cols[4].metric("Coverage %", f"{outcome.coverage_pct * 100:.2f}%")

    # --- Per-tactic bar chart ---
    tactics = [tb.tactic for tb in outcome.per_tactic]
    detected = [tb.detected for tb in outcome.per_tactic]
    missed = [tb.missed for tb in outcome.per_tactic]
    fig = go.Figure()
    fig.add_trace(
        go.Bar(name="Detected", x=tactics, y=detected, marker_color="#4caf50")
    )
    fig.add_trace(
        go.Bar(name="Missed", x=tactics, y=missed, marker_color="#e53935")
    )
    fig.update_layout(
        barmode="stack",
        height=420,
        margin=dict(l=120, r=40, t=20, b=200),
        xaxis_tickangle=-60,
        xaxis=dict(title="Tactic"),
        yaxis=dict(title="Technique count"),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1.0),
    )
    st.plotly_chart(fig, use_container_width=True)

    # --- Recommendations (plain-language) ---
    import html
    st.subheader("Recommended next sources")
    if outcome.recommendations:
        for rec in outcome.recommendations:
            rec_safe = html.escape(str(rec))
            st.markdown(f"- {rec_safe}")
    else:
        st.info("No acquisition recommendations -- all missed techniques lack a mappable source.")

    # --- Missed-technique detail ---
    missed_techs = [t for t in outcome.techniques if t.status == "missed"]
    if missed_techs:
        with st.expander(f"Missed techniques ({len(missed_techs)})", expanded=False):
            st.dataframe(
                [
                    {
                        "technique": t.attack_id,
                        "name": t.name,
                        "tactic": t.tactic,
                        "confidence": f"{t.confidence:.4f}",
                        "contributing_sources": ", ".join(t.contributing_sources) or "—",
                    }
                    for t in missed_techs
                ],
                use_container_width=True,
                hide_index=True,
            )


def render_simulation_view(
    session: Any,
    config: dict[str, Any],
) -> None:
    """Render the APT Simulation dashboard.

    The group is picked in the sidebar; pressing "Run simulation" triggers
    :func:`simulate_apt_attack` in a spinner.  Errors are surfaced via
    ``st.error`` rather than crashing the page.

    Args:
        session: An open SQLAlchemy session.
        config: The live config mapping.
    """
    st.header("APT Simulation")
    st.caption(
        "Simulate a named APT group's techniques against your current coverage. "
        "The view shows detected vs. missed per tactic, greedy marginal-gain "
        "acquisition advice, and the missed technique detail."
    )

    group_id = _group_picker(session, config)

    if st.sidebar.button("Run simulation", type="primary"):
        with st.spinner(f"Simulating {group_id}..."):
            try:
                # simulate_apt_attack persists when persist=True; it owns its
                # own write transaction.  We pass the caller's session so the
                # view's (read-only) engine is reused.
                outcome = simulate_apt_attack(
                    group_id,
                    session=session,
                    config=config,
                    persist=True,
                )
            except Exception as exc:  # surface, don't crash
                st.error(f"Simulation failed for {group_id}: {exc}")
                st.stop()
                return

        st.success(f"Simulation complete: {outcome.group_id}")
        _render_outcome(outcome)
    else:
        st.info("Select an APT group in the sidebar and click **Run simulation**.")
