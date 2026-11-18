"""ATT&CK Coverage Mapper - Streamlit entry point.

Multi-page shell.  Each surface lives in :mod:`src.visualization.views`; this
module only boots the path, proves database connectivity (Phase 0 gate), owns
the config sidebar (which writes back to ``config.yaml``), and routes to the
selected page.

Run from repo root:  streamlit run src/visualization/app.py
"""
from __future__ import annotations

import contextlib
import os
import sys
import time
from pathlib import Path
from typing import Any

# Entry-point path bootstrap so `database`/`src` resolve when Streamlit runs
# this file directly (acceptable here; library modules never do this).
#
# BOTH roots are required: `database.*` lives under src/, while `src.*` needs
# the repository root. Streamlit Cloud runs this file with neither on sys.path
# and no PYTHONPATH, so adding only one of them fails at import time -- a
# regression that has already shipped twice (parents[1] broke `src.*`, then
# parents[2] broke `database.*`). Keep both.
_REPO_ROOT = Path(__file__).resolve().parents[2]
for _path in (_REPO_ROOT, _REPO_ROOT / "src"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import streamlit as st  # noqa: E402

# Must be the first Streamlit command; Streamlit asserts on this.
st.set_page_config(page_title="ATT&CK Coverage Mapper", layout="wide")

try:
    from sqlalchemy import select, text
    from sqlalchemy.orm import Session

    from database.session import (
        database_url,
        make_engine,
        session_scope,
        verify_schema,
    )
    from src.config_loader import load_config
    from src.visualization.views.styles import inject_css
except Exception as exc:  # noqa: BLE001 -- a deploy must explain itself
    # Streamlit renders an unhandled module-level exception with the message
    # redacted, which hides the one line that explains a broken deploy. Show
    # it instead.
    st.error(
        "Startup failed while importing the application modules:\n\n"
        f"```\n{type(exc).__name__}: {exc}\n```\n\n"
        "This usually means the deployed tree is inconsistent -- an old module "
        "beside a new one. Rebuild the app, then hard-refresh the page."
    )
    st.stop()

try:
    from database.session import BUILD_TAG
except ImportError:
    # The deployed database module predates the marker, i.e. the host is
    # serving a stale file. Say so rather than hiding it.
    BUILD_TAG = "stale-deploy"


def _normalise_database_url_env() -> None:
    """Rewrite a bare ``postgresql://`` URL to ``postgresql+psycopg://``.

    Hosted consoles (Neon included) copy a ``postgresql://`` connection string.
    SQLAlchemy resolves that scheme to psycopg2, which this project does not
    install, so it must become ``postgresql+psycopg://`` before
    :func:`database.session.database_url` validates it.

    Done here as well as in ``database.session`` because the entry point is the
    one file that is guaranteed to redeploy: if the host serves a stale
    ``database/session.py``, the scheme is still corrected and the app still
    starts. Idempotent, and only touches the environment.
    """
    raw = os.environ.get("DATABASE_URL", "")
    for scheme in ("postgresql", "postgres"):
        prefix = f"{scheme}://"
        if raw.startswith(prefix):
            os.environ["DATABASE_URL"] = "postgresql+psycopg://" + raw[len(prefix):]
            return


_normalise_database_url_env()

#: Driver schemes the entry point accepts. Kept local (rather than imported from
#: ``database.session``) so startup does not depend on that module being
#: current -- see :func:`_normalise_database_url_env`.
_ALLOWED_DATABASE_DRIVERS = (
    "sqlite",
    "sqlite+pysqlite",
    "postgresql",
    "postgres",
    "postgresql+psycopg",
)

#: Connection attempts before the startup probe gives up.
_CONNECT_ATTEMPTS = 3

CONFIG_PATH = str(_REPO_ROOT / "config.yaml")

# Inject shared CSS
inject_css()


@st.cache_resource
def get_engine(url: str):
    """Validate URL scheme and create engine."""
    from sqlalchemy.engine import make_url

    try:
        parsed = make_url(url)
        if parsed.drivername not in _ALLOWED_DATABASE_DRIVERS:
            raise ValueError(f"unsupported database driver: {parsed.drivername}")
    except Exception as exc:
        raise ValueError(f"invalid DATABASE_URL: {exc}") from exc
    return make_engine(url)


def _load_config_cached() -> dict[str, Any]:
    """Load config.yaml, cached so toggles only recompute on change."""
    return load_config(CONFIG_PATH)


def _write_config(config: dict[str, Any]) -> bool:
    """Persist an in-memory config dict back to ``config.yaml``.

    PyYAML round-trip may reorder/drop comments; acceptable for the demo.
    Preserves ``collected_log_sources`` by converting frozenset to sorted list.
    Returns True on success, False on failure (caller surfaces via st.error).
    """
    import yaml

    try:
        serializable = dict(config)
        # Convert frozenset to sorted list for YAML serialization
        val = serializable.get("collected_log_sources")
        if isinstance(val, (frozenset, set)):
            serializable["collected_log_sources"] = sorted(val)

        with open(CONFIG_PATH, "w", encoding="utf-8") as fh:
            yaml.safe_dump(
                serializable,
                fh,
                default_flow_style=False,
                sort_keys=False,
            )
        return True
    except Exception as exc:  # noqa: BLE001 -- surfaced to the user
        st.error(f"Could not save config.yaml: {exc}")
        return False


# ---------------------------------------------------------------------------
# Sidebar navigation & config
# ---------------------------------------------------------------------------
# The sidebar has two clearly separated sections:
#   1. Page navigation (top) -- prominent radio buttons
#   2. Log-source configuration (bottom, inside an expander) -- toggling a
#      source is the key demo beat ("toggle source -> coverage responds").
#      Toggles write back to config.yaml, which Streamlit picks up on the next
#      rerun.
# ---


def _render_config_section(config: dict[str, Any]) -> dict[str, Any]:
    """Render log-source enablement checkboxes inside a sidebar expander.

    Reads ``enabled_log_sources`` from *config* and writes the user's toggles
    back to ``config.yaml`` via :func:`_write_config`.  Scope and threshold are
    shown read-only.

    Args:
        config: The current config dict (mutated in a copy).

    Returns:
        The config dict reflecting the latest sidebar state.
    """
    with st.sidebar.expander("Configuration", expanded=False):
        st.caption("Log sources included in coverage calculation")

        sources = dict(config.get("enabled_log_sources", {}))
        changed = False
        for fmt in sorted(sources):
            default = bool(sources.get(fmt, True))
            now = st.checkbox(
                fmt, value=default, key=f"src_{fmt}"
            )
            if now != default:
                sources[fmt] = now
                changed = True

        scope = config.get("platform_scope", "all")
        threshold = config.get("detection_confidence_threshold", 0.6)
        st.markdown(f"**Platform scope:** `{scope}`")
        st.markdown(f"**Confidence threshold:** `{threshold}`")

        if changed:
            new_config = dict(config)
            new_config["enabled_log_sources"] = sources
            if _write_config(new_config):
                st.success("config.yaml updated")
                st.rerun()
            return new_config

    return config


# --- Page router ---
from src.visualization.views import (  # noqa: E402
    anomaly as _anomaly,
    coverage as _coverage,
    gap as _gap,
    hunt as _hunt,
    simulation as _simulation,
)

PAGES: dict[str, Any] = {
    "Coverage Overview": _coverage.render_coverage_view,
    "APT Simulation": _simulation.render_simulation_view,
    "Hunt Queries": _hunt.render_hunt_view,
    "Gap Analysis": _gap.render_gap_view,
    "Anomaly Detection": _anomaly.render_anomaly_view,
}


# ---------------------------------------------------------------------------
# DB connectivity (Phase 0 gate)
# ---------------------------------------------------------------------------
# Configuration errors are surfaced with their real message. An unhandled
# exception here is rendered by Streamlit as a redacted traceback, which hides
# the one line that explains a misconfigured DATABASE_URL.
try:
    url: str = database_url()
except Exception as exc:  # noqa: BLE001 -- surface, don't crash
    st.error(f"Database configuration error: {exc}")
    st.stop()

# Serverless Postgres can drop the first connection while its compute wakes.
# Retry a few times before declaring the database unreachable.
connected = False
last_error: Exception | None = None
for _attempt in range(1, _CONNECT_ATTEMPTS + 1):
    try:
        engine = get_engine(url)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        # `SELECT 1` only proves the server is awake. Verify the application
        # schema too, so an empty or wrong database fails loudly instead of
        # rendering a blank dashboard (the Streamlit Cloud failure this guard
        # exists for).
        verify_schema(engine)
        connected = True
        break
    except Exception as exc:  # noqa: BLE001 -- surface, don't crash
        last_error = exc
        engine = None  # type: ignore[assignment]
        if _attempt < _CONNECT_ATTEMPTS:
            time.sleep(2 * _attempt)

if not connected:
    st.error(
        f"Database connection failed after {_CONNECT_ATTEMPTS} attempts: "
        f"{last_error}"
    )

# Visible in both the connected and failed states, so a deploy can be
# identified without reading logs.
st.caption(f"build `{BUILD_TAG}`")

if connected:
    try:
        from sqlalchemy.engine import make_url
        safe_url = make_url(url).render_as_string(hide_password=True)
    except Exception:
        safe_url = url
    st.success(f"Database connected and schema verified: `{safe_url}`")

st.markdown("---")

if not connected:
    st.warning("Database not connected -- the dashboard views require a live DB.")
    st.stop()

# --- Render ---
config = _load_config_cached()

page = st.sidebar.radio(
    "Page",
    options=list(PAGES.keys()),
    label_visibility="collapsed",
    key="nav_page",
)

st.sidebar.markdown("---")

config = _render_config_section(config)


@contextlib.contextmanager
def _bound_session(engine: Any) -> Session:
    """Open a short-lived, committing session bound to *engine*.

    Delegates to :func:`database.session.session_scope` so the dashboard shares
    one transactional contract with the rest of the codebase.  The commit is
    load-bearing: ``simulate_apt_attack(..., persist=True)`` only *stages* the
    new SimulationResult and its SimulationTechnique rows on the caller's
    session, so a close-without-commit silently discarded every run made from
    the dashboard (the UI still reported success because the outcome object was
    already populated in memory).
    """
    with session_scope(engine) as session:
        yield session


def _result_id_picker(session: Any) -> int:
    """Pick which simulation result to render (defaults to most recent)."""
    from src.database.models import SimulationResult

    max_id = session.execute(
        select(SimulationResult.id).order_by(SimulationResult.id.desc())
    ).scalar()
    if max_id is None:
        st.warning("No simulation results in the database yet.")
        st.stop()
    return int(
        st.number_input(
            "Simulation result id",
            min_value=1,
            value=int(max_id),
            step=1,
            help="The simulation_results.id to generate hunt queries for.",
        )
    )


if page == "Coverage Overview":
    with _bound_session(engine) as session:
        PAGES[page](session, config)
elif page == "APT Simulation":
    with _bound_session(engine) as session:
        PAGES[page](session, config)
elif page == "Hunt Queries":
    with _bound_session(engine) as session:
        result_id = _result_id_picker(session)
        PAGES[page](result_id, session=session, config=config)
elif page == "Gap Analysis":
    with _bound_session(engine) as session:
        PAGES[page](session, config)
elif page == "Anomaly Detection":
    PAGES[page](config=config)

st.markdown("---")
st.caption("Sample/synthetic data only. No real organizational logs are ingested.")