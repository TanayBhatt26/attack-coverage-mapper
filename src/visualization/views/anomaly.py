"""Streamlit Anomaly Detection view (future phase).

Renders a dataframe of flagged anomalies with anomaly scores, a bar chart
of scores, a toggle between anomalies-only and all-events, and summary
metric cards.

The detector trains an Isolation Forest on feature vectors extracted from
parsed LogEvent objects. See :mod:`src.analysis.anomaly_detector` for the
model contract.

Frozen contract (this module): 5th dashboard page "Anomaly Detection".

Layout:
    1. Metric cards: total events, anomaly count, anomaly rate.
    2. Toggle: "Show only anomalies" checkbox.
    3. st.dataframe of events + anomaly score.
    4. Bar chart of anomaly scores (Plotly).
"""

from __future__ import annotations

from typing import Any

import numpy as np
import plotly.graph_objects as go
import streamlit as st

from src.analysis.anomaly_detector import AnomalyDetector
from src.parser.log_event_bridge import LogEvent


# Synthetic demo events used when no real parsed events are available.
# In a production deployment this view would read from the DB or a
# live parser stream; the project is demo/synthetic-only (see README).
def _demo_events(n: int = 200) -> list[LogEvent]:
    """Generate a small synthetic event set for the demo view.

    The first ``n - 5`` events are "normal" (one common action); the last
    5 are injected anomalies with distinct actions, many extensions, and
    large byte counts.
    """
    rng = np.random.default_rng(7)
    events: list[LogEvent] = []
    for i in range(n - 5):
        events.append(
            LogEvent(
                event_action="logon_failure",
                source_format="evtx",
                extensions={"event_id": "4625", "substatus": str(rng.integers(0, 8))},
                timestamp=f"2026-08-27T{int(rng.integers(8, 18)):02d}:30:00Z",
                bytes_in=int(rng.integers(0, 1000)),
            )
        )
    # Injected anomalies
    for i in range(5):
        events.append(
            LogEvent(
                event_action=f"rare_action_{i}",
                source_format="zeek",
                extensions={f"ext_{j}": j for j in range(15)},
                timestamp=f"2026-08-27T{int(rng.integers(0, 5)):02d}:00:00Z",
                source_ip="192.168.1.100",
                process_name=f"suspicious_{i}.exe",
                bytes_in=int(rng.integers(500000, 1000000)),
                bytes_out=int(rng.integers(500000, 1000000)),
            )
        )
    return events


def _render_score_bar(scores: list[float]) -> go.Figure:
    """Build a bar chart of anomaly scores.

    Args:
        scores: Anomaly scores (one per event, lower = more anomalous).

    Returns:
        A Plotly Figure ready for ``st.plotly_chart``.
    """
    fig = go.Figure()
    fig.add_trace(
        go.Bar(
            y=list(range(len(scores))),
            x=scores,
            orientation="h",
            marker_color=[
                "#e53935" if s < 0 else "#4caf50" for s in scores
            ],
        )
    )
    fig.update_layout(
        height=max(200, 12 * len(scores) + 80),
        margin=dict(l=40, r=40, t=20, b=40),
        xaxis=dict(title="Anomaly score (lower = more anomalous)"),
        yaxis=dict(title="Event index", visible=False),
    )
    return fig


def render_anomaly_view(
    session: Any = None,
    config: dict[str, Any] | None = None,
) -> None:
    """Render the Anomaly Detection dashboard.

    Trains (or loads) an Isolation Forest on parsed LogEvents, predicts
    anomaly labels/scores, and renders the dashboard. When no real events
    are provided, a synthetic demo set is generated (the project is
    demo/synthetic-only).

    Args:
        session: Unused (kept for view-signature consistency).
        config: The live config mapping (drives anomaly_detection settings).
        events: Parsed LogEvent objects, or None to use the demo set.
    """
    st.header("Anomaly Detection")
    st.caption(
        "Isolation Forest over parsed LogEvent feature vectors. "
        "Lower anomaly score = more anomalous. "
        "This view uses synthetic demo data (see README)."
    )

    # Resolve config
    cfg = dict(config or {})
    ad_cfg = cfg.get("anomaly_detection", {})
    contamination = ad_cfg.get("contamination", 0.05)
    random_state = ad_cfg.get("random_state", 42)
    model_path = ad_cfg.get("model_path", "models/isolation_forest.joblib")

    # For the demo we generate a synthetic event set. In a real deployment
    # you would read parsed events from a DB or a live parser stream.
    events = _demo_events(200)

    # Train a fresh model for the demo (no persistence in demo mode).
    det = AnomalyDetector(contamination=contamination, random_state=random_state)
    det.train(events)

    # Predict
    preds = det.predict(events)

    # Merge into rows for the dataframe
    rows = []
    for ev, pr in zip(events, preds):
        rows.append(
            {
                "event_id": ev.event_id[:12],
                "source_format": ev.source_format,
                "event_action": ev.event_action,
                "extensions": len(ev.extensions),
                "hour": AnomalyDetector._parse_hour(ev.timestamp),
                "label": pr["label"],
                "score": round(pr["score"], 4),
            }
        )

    # --- Metric cards ---
    total = len(rows)
    anomalies = [r for r in rows if r["label"] == -1]
    anomaly_count = len(anomalies)
    rate = anomaly_count / total if total else 0.0

    cols = st.columns(3)
    cols[0].metric("Total events", total)
    cols[1].metric("Anomalies", anomaly_count)
    cols[2].metric("Anomaly rate", f"{rate * 100:.1f}%")

    # --- Toggle: anomalies only ---
    only_anomalies = st.checkbox("Show only anomalies", value=False)
    display_rows = anomalies if only_anomalies else rows

    # --- Dataframe ---
    st.dataframe(
        display_rows,
        use_container_width=True,
        hide_index=True,
    )

    # --- Score bar chart ---
    st.subheader("Anomaly scores")
    scores = [r["score"] for r in display_rows]
    st.plotly_chart(_render_score_bar(scores), use_container_width=True)

    with st.expander("How it works", expanded=False):
        st.markdown(
            "- **Features**: event_action (one-hot), source_format (one-hot), "
            "extension_count, hour_of_day, day_of_week, binary presence flags "
            "(source_ip, dest_ip, username, process_name, message), "
            "bytes_in, bytes_out.\n"
            "- **Model**: sklearn Isolation Forest, contamination "
            f"`{contamination}`, random_state `{random_state}`.\n"
            "- **Score**: anomaly score from the forest (lower = more anomalous).\n"
            "- **Persistence**: in production, train on a sliding window and "
            f"persist to `{model_path}` via joblib.\n"
        )
