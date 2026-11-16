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
    box-sizing: border-box;
}

/* Ensure main content doesn't cause horizontal overflow */
.main {
    overflow-x: hidden;
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

/* Make sidebar scrollable on small screens so all nav items remain reachable */
[data-testid="stSidebar"] {
    overflow-y: auto;
}

/* Reduce sidebar header height on small screens */
[data-testid="stSidebar"] .stMarkdown > div:first-child {
    margin-top: 0.5rem;
}

/* Compact the navigation radio group on small screens */
@media (max-width: 768px) {
    [data-testid="stSidebar"] .stRadio > div {
        gap: 0.25rem;
    }
    [data-testid="stSidebar"] .stRadio label {
        font-size: 0.85rem;
        padding: 0.4rem 0.5rem;
    }
    [data-testid="stSidebar"] [data-testid="stSidebarNav"] {
        padding-top: 0.5rem;
    }
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
    box-sizing: border-box;
}

.metric-value {
    font-size: 1.5rem;
    font-weight: 700;
    color: #f8fafc;
    line-height: 1.2;
    word-wrap: break-word;
}

.metric-label {
    font-size: 0.75rem;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-top: 0.25rem;
    word-wrap: break-word;
}

/* Colored source badges (hunt queries) */
.badge {
    display: inline-flex;
    align-items: center;
    padding: 3px 8px;
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
    box-sizing: border-box;
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
    box-sizing: border-box;
}
.warning-banner {
    background-color: #0b1016;
    color: #e2e8f0;
    border: 1px solid #1f2937;
    border-left: 4px solid #d97706;
    padding: 1rem;
    margin: 1rem 0;
    border-radius: 6px;
    box-sizing: border-box;
}

/* Inline code */
code {
    background-color: #0b1016;
    color: #e2e8f0;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 0.85em;
    font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
    word-wrap: break-word;
}

/* Tables */
.stDataFrame {
    border: 1px solid #1f2937 !important;
    border-radius: 6px !important;
    overflow-x: auto !important;
}
.stDataFrame th {
    background-color: #111827 !important;
    color: #e2e8f0 !important;
    font-weight: 600;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    white-space: nowrap;
}
.stDataFrame td {
    color: #e2e8f0 !important;
    border-bottom: 1px solid #1f2937 !important;
}

/* Responsive adjustments for small screens */
@media (max-width: 768px) {
    .main .block-container {
        padding-top: 1rem;
        padding-right: 1rem;
        padding-bottom: 1.5rem;
        padding-left: 1rem;
    }

    .section-title {
        margin: 1.25rem 0 0.5rem 0;
        font-size: 0.8rem;
    }

    .badge {
        font-size: 0.7rem;
        padding: 2px 6px;
        white-space: normal;
    }

    .stDataFrame th {
        font-size: 0.65rem;
        padding: 4px 6px;
    }

    .stDataFrame td {
        font-size: 0.7rem;
        padding: 4px 6px;
    }

    /* Stack Streamlit columns vertically on small screens */
    [data-testid="stHorizontalBlock"] {
        flex-direction: column !important;
        gap: 0.5rem !important;
    }
    [data-testid="stColumn"] {
        width: 100% !important;
        flex: 1 1 100% !important;
        min-width: 100% !important;
    }
    [data-testid="stMetric"] {
        width: 100% !important;
    }
}
</style>
"""

def inject_css() -> None:
    """Inject shared CSS into Streamlit app. Call once in app.py before views."""
    st.markdown(CSS, unsafe_allow_html=True)
