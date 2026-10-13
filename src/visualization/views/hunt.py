"""Streamlit Hunt view (Phase 7).

Renders the work-list invariant emitted by
:func:`detections.hunt_query_generator.export_all_queries` -- exactly one hunt
query per *missed* technique in a simulation run -- as a gap list plus a
per-technique expander carrying the inert query, a colored source badge, the
built-in copy widget, the attribution block, and a link to the remediation
bundle in Gap Analysis.

The frozen dashboard contract is pinned in
``research/p5-wave1-full-results.md`` agent-436 (derived from the normative
``docs/_phase4_handoff.md``).  This module is a pure renderer: it owns no
pipeline logic and never mutates the database.

Layout (contract §1-§6):
    1. Gap list: one row per missed technique, ordered
       ``technique_attack_id ASC``; count MUST equal ``missed_count``.
    2. Per-technique ``st.expander(f"{technique_attack_id} — {technique_name}")``.
    3. Body: ``st.code(query, language=query_language)`` (built-in copy widget),
       a colored source badge, and the attribution block.
    4. Attribution block varies by ``attribution_label``:
       - community-sourced: title, author, rule_id, repo_url, DRL 1.1 license,
         statement.
       - hand-curated: author="ATT&CK Coverage Mapper", license="project-original".
       - generic: license="template — not a detection rule"; UNREVIEWED header.
    5. Remediation link: shows candidate sources and remediation category.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import streamlit as st

from src.detections.hunt_query_generator import export_all_queries

# Source-badge palette (contract §5).  Keys are the frozen attribution-label
# set; values are (background, foreground) hex pairs chosen for Streamlit's
# default theme so each pill reads distinctly.
_BADGE_COLORS: dict[str, tuple[str, str]] = {
    "community-sourced": ("#1b4332", "#95d5b2"),
    "hand-curated": ("#1a3a5c", "#90caf9"),
    "generic": ("#4a3b12", "#f0d878"),
}

# License strings (contract §4) -- pinned verbatim so exports are consistent.
_LICENSE_COMMUNITY = "Detection Rule License (DRL) 1.1"
_LICENSE_HAND_CURATED = "project-original"
_LICENSE_GENERIC = "template — not a detection rule"


def _render_attribution(label: str, query_rec: Mapping[str, Any]) -> None:
    """Render the attribution block for one query record (contract §4)."""
    attr = dict(query_rec.get("attribution") or {})

    if label == "community-sourced":
        import html
        from urllib.parse import urlparse

        title = attr.get("title") or "Untitled"
        author = attr.get("author") or "unknown"
        rule_id = attr.get("rule_uuid") or query_rec.get("source_rule_id") or "—"
        repo_url = attr.get("rule_url") or attr.get("rule_set_url") or "—"
        statement = (
            f"{attr.get('rule_set_url', repo_url)} © authors, "
            f"licensed under {_LICENSE_COMMUNITY}"
        )

        title_safe = html.escape(str(title))
        author_safe = html.escape(str(author))
        rule_id_safe = html.escape(str(rule_id))
        statement_safe = html.escape(str(statement))

        repo_url_safe = str(repo_url)
        try:
            parsed = urlparse(repo_url_safe)
            if parsed.scheme not in ("https", "http"):
                repo_url_safe = "#invalid-url"
        except Exception:
            repo_url_safe = "#invalid-url"

        st.markdown(
            f"**Title:** {title_safe}  \n"
            f"**Author:** {author_safe}  \n"
            f"**Rule ID:** `{rule_id_safe}`  \n"
            f"**Source:** [{repo_url_safe}]({repo_url_safe})  \n"
            f"**License:** {_LICENSE_COMMUNITY}  \n"
            f"**Statement:** {statement_safe}"
        )
    elif label == "hand-curated":
        st.markdown(
            f"**Author:** ATT&CK Coverage Mapper  \n"
            f"**License:** {_LICENSE_HAND_CURATED}"
        )
    else:
        # generic
        st.markdown(
            f"**License:** {_LICENSE_GENERIC}"
        )


def _render_remediation_link(
    technique_attack_id: str,
    closable_by: tuple[str, ...],
    config: dict[str, Any],
) -> None:
    """Render a remediation summary linking to Gap Analysis remediation bundles.

    Args:
        technique_attack_id: The technique ID.
        closable_by: Candidate disabled sources from the query record.
        config: Live config mapping (for collected_log_sources).
    """
    collected_sources = config.get("collected_log_sources")
    enabled_sources = frozenset(
        s for s, v in config.get("enabled_log_sources", {}).items() if v
    )

    if not closable_by:
        st.info("No candidate source reaches threshold — see Gap Analysis → Unresolved")
        return

    st.markdown("**Remediation (see Gap Analysis → Remediation Bundles):**")
    for src in closable_by:
        if collected_sources is None:
            status = "⚪ Status unknown"
            action = "Investigate status"
        elif src in collected_sources:
            if src in config.get("enabled_log_sources", {}):
                status = "🚨 Validation error (enabled in closable_by)"
            else:
                status = "🟢 Collected — disabled"
            action = "Enable"
        else:
            status = "🔴 Not collected"
            action = "Acquire"
        st.markdown(f"- `{src}` — {status} → {action}")

    st.caption(
        "Full remediation details in Gap Analysis → Remediation Bundles tab."
    )


def _render_technique(
    technique_attack_id: str,
    technique_name: str,
    query_rec: Mapping[str, Any],
    config: dict[str, Any],
) -> None:
    """Render one per-technique expander (contract §2, §3)."""
    label = query_rec["attribution_label"]
    query = query_rec["query"]
    query_language = query_rec["query_language"]
    closable_by = tuple(query_rec.get("closable_by", ()))

    with st.expander(f"{technique_attack_id} — {technique_name}", expanded=False):
        # Colored source badge (contract §5).
        import html
        label_safe = html.escape(str(label))
        bg, fg = _BADGE_COLORS.get(label, ("#333333", "#dddddd"))
        st.markdown(
            f"<span style='"
            f"background:{bg};color:{fg};"
            f"padding:2px 10px;border-radius:10px;"
            f"font-size:0.8em;font-weight:600;'>"
            f"{label_safe}</span>",
            unsafe_allow_html=True,
        )

        # UNREVIEWED header on generic queries (contract §4).
        if label == "generic":
            st.warning("UNREVIEWED — inspect before use. This is a placeholder template, not a detection rule.")

        # Inert query + built-in copy widget (contract §6).
        st.code(query, language=query_language)

        # Attribution block (contract §4).
        st.markdown("**Attribution**")
        _render_attribution(label, query_rec)

        st.markdown("---")
        # Remediation link (Phase 7)
        _render_remediation_link(technique_attack_id, tuple(query_rec.get("closable_by", ())), config)


def render_hunt_view(
    result_id: int,
    *,
    session: Any = None,
    config: Mapping[str, Any] | None = None,
    rules: list[Any] | None = None,
    sigma_rules_dir: str | None = None,
) -> None:
    """Render the full Hunt dashboard for a simulation run."""
    config = dict(config) if config else {}
    st.header("Hunt — missed techniques")
    st.caption(
        "One inert hunt query per missed technique. "
        "Community-sourced rules are licensed under DRL 1.1; inspect every "
        "query before running it against real logs."
    )

    with st.spinner("Generating hunt queries..."):
        queries = export_all_queries(
            result_id,
            session=session,
            config=config,
            rules=rules,
            sigma_rules_dir=sigma_rules_dir,
        )

    if not queries:
        st.info("No missed techniques for this run -- nothing to hunt.")
        return

    # --- Gap list (contract §1) ---
    st.subheader(f"Gap list ({len(queries)} missed)")
    gap_rows = [
        {
            "technique_attack_id": tid,
            "query_language": rec["query_language"],
            "attribution_label": rec["attribution_label"],
            "source_rule_id": rec.get("source_rule_id"),
            "closable_by": ", ".join(rec["closable_by"]) or "—",
            "confidence": rec["confidence"],
        }
        for tid, rec in queries.items()
    ]
    st.dataframe(gap_rows, use_container_width=True, hide_index=True)
    st.markdown("---")

    # --- Per-technique expanders (contract §2) ---
    st.subheader("Queries by technique")
    for tid, rec in queries.items():
        name = rec.get("technique_name") or tid
        _render_technique(tid, name, rec, config)