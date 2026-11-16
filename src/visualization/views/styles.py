"""Shared styling module for ATT&CK Coverage Mapper dashboard.

Injects minimal CSS that complements Streamlit's native theme without
targeting Streamlit's internal components (expanders, theme selector,
checkboxes, etc.) -- those are left alone so Streamlit renders them
correctly.  Provides only custom component classes Streamlit does not
supply natively (section headers, dividers, metric cards, badges).

Call :func:`inject_css` once in ``app.py`` before rendering views.
"""

from typing import Any

import streamlit as st

CSS = """
<style>
/* ============================================================================
   Base page
   ========================================================================== */
.main .block-container {
    padding-top: 1.5rem;
    padding-right: 1.5rem;
    padding-bottom: 2.5rem;
    padding-left: 1.5rem;
    max-width: 100%;
}

/* ============================================================================
   Sidebar
   ========================================================================== */
[data-testid="stSidebar"] {
    background-color: #0b1016;
    border-right: 1px solid #1f2937;
}

/* Sidebar section headers (only our own h2/h3, not Streamlit internals) */
[data-testid="stSidebar"] h2,
[data-testid="stSidebar"] h3 {
    color: #e2e8f0 !important;
    font-size: 0.875rem;
    font-weight: 600;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    margin-top: 1.5rem;
    margin-bottom: 0.75rem;
    padding-bottom: 0.375rem;
    border-bottom: 1px solid #1f2937;
}

/* ============================================================================
   Custom components (Streamlit does not provide these natively)
   ========================================================================== */

/* Section header with underline divider, used inside main content */
.section-title {
    font-size: 0.875rem;
    font-weight: 600;
    color: #94a3b8;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    margin: 1.75rem 0 0.75rem 0;
    padding-bottom: 0.375rem;
    border-bottom: 1px solid #1f2937;
}

/* Horizontal section divider */
.section-divider {
    margin: 2rem 0;
    border: none;
    border-top: 1px solid #1f2937;
}

/* Metric-style card for custom KPI blocks */
.metric-card {
    background-color: #0b1016;
    border: 1px solid #1f2937;
    border-radius: 6px;
    padding: 1rem 1.25rem;
    margin-bottom: 0.75rem;
}

.metric-value {
    font-size: 1.5rem;
    font-weight: 700;
    color: #f8fafc;
    line-height: 1.2;
}

.metric-label {
    font-size: 0.75rem;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-top: 0.25rem;
}

/* Colored source badges (hunt queries) */
.badge {
    display: inline-flex;
    align-items: center;
    padding: 3px 10px;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 0.025em;
    white-space: nowrap;
}
.badge-community-sourced { background: #1b4332; color: #95d5b2; }
.badge-hand-curated    { background: #1a3a5c; color: #90caf9; }
.badge-generic         { background: #4a3b12; color: #f0d878; }

/* Query code block wrapper */
.query-block {
    background-color: #0b1016;
    border: 1px solid #1f2937;
    border-radius: 6px;
    padding: 1rem 1.25rem;
    font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
    font-size: 0.85rem;
    line-height: 1.5;
    overflow-x: auto;
    margin-bottom: 1rem;
}

/* Status / informational banners */
.info-banner {
    background-color: #0b1016;
    color: #e2e8f0;
    border: 1px solid #1f2937;
    border-left: 4px solid #3b82f6;
    padding: 1rem;
    margin: 1rem 0;
    border-radius: 6px;
}
.warning-banner {
    background-color: #0b1016;
    color: #e2e8f0;
    border: 1px solid #1f2937;
    border-left: 4px solid #d97706;
    padding: 1rem;
    margin: 1rem 0;
    border-radius: 6px;
}

/* Inline code */
code {
    background-color: #0b1016;
    color: #e2e8f0;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 0.85em;
    font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
}

/* Tables */
.stDataFrame {
    border: 1px solid #1f2937 !important;
    border-radius: 6px !important;
    overflow: hidden !important;
}
.stDataFrame th {
    background-color: #111827 !important;
    color: #e2e8f0 !important;
    font-weight: 600;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}
.stDataFrame td {
    color: #e2e8f0 !important;
    border-bottom: 1px solid #1f2937 !important;
}
</style>
"""

def inject_css() -> None:
    """Inject shared CSS into Streamlit app. Call once in app.py before views."""
    st.markdown(CSS, unsafe_allow_html=True)
