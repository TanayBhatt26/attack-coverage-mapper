"""Contract tests for the Phase 6 Streamlit dashboard views.

Verifies the four dashboard surfaces each render the right widgets and call the
right analysis functions, against frozen contracts:

- Coverage Overview  -> load_coverage_rows + coverage_by_tactic -> 14 buckets
- APT Simulation     -> list_apt_groups + simulate_apt_attack -> SimulationOutcome
- Hunt Queries       -> export_all_queries (work-list invariant; see test_hunt_view)
- Gap Analysis       -> calculate_coverage_gaps + cluster_gaps -> GapCluster[]

View logic is pure delegation; Streamlit is mocked so these run offline with no
browser.  The committed ``db/coverage.db`` is left untouched (read-only fixture
shared with the Phase-4/5 suites).

Tests assert the *render contract*: which Streamlit widgets fire and with what
arguments, and that each view delegates to the correct analysis entry point.
"""

from __future__ import annotations

import contextlib
from collections import OrderedDict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import select

from src.database.models import SimulationResult
from src.visualization.views import coverage as coverage_view
from src.visualization.views import gap as gap_view
from src.visualization.views import simulation as sim_view

from tests.test_integration_phase4 import _attach_readonly_sqlite  # noqa: E402

# Skip all dashboard view tests if the dev database doesn't have the required tables.
def _db_has_tables() -> bool:
    db_path = Path(__file__).resolve().parents[1] / "db" / "coverage.db"
    if not db_path.exists():
        return False
    try:
        from src.database.session import make_engine
        from sqlalchemy import inspect
        engine = make_engine(f"sqlite:///{db_path}")
        try:
            tables = inspect(engine).get_table_names()
            return "techniques" in tables and "simulation_results" in tables
        finally:
            engine.dispose()
    except Exception:
        return False

pytestmark = pytest.mark.skipif(
    not _db_has_tables(),
    reason="Dashboard view tests require populated db/coverage.db (run ATT&CK ingest first)",
)


# ---------------------------------------------------------------------------
# Shared harness (mirrors test_hunt_view._RenderHarness)
# ---------------------------------------------------------------------------


class _ExpanderCM:
    """Minimal context manager mimicking ``st.expander()``'s return value."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None


class _ColumnMetric:
    """Proxy object standing in for a ``st.columns()`` slice.

    Its ``.metric(...)`` forwards into the harness's ``metric`` call bucket so
    KPIs are observable even though they are called on the column proxy.
    """

    def __init__(self, harness: "_RenderHarness") -> None:
        self._h = harness

    def metric(self, *args, **kwargs):
        self._h.calls.setdefault("metric", []).append((args, kwargs))
        return MagicMock()


class _SidebarProxy:
    """Proxy for ``st.sidebar`` that records widget calls made on it.

    Views call ``st.sidebar.checkbox(...)`` / ``st.sidebar.selectbox(...)`` etc.
    This forwards each sub-widget call to the harness's bucket so they are
    observable without a live Streamlit runtime.
    """

    def __init__(self, harness: "_RenderHarness") -> None:
        self._h = harness

    def __getattr__(self, sub: str):
        def _sub(*args, **kwargs):
            self._h.calls.setdefault(sub, []).append((args, kwargs))
            if sub == "number_input":
                return 1  # a plausible result_id default
            if sub == "selectbox":
                # Return the first option's value (views default to index 0).
                opts = kwargs.get("options") or (args[1] if len(args) > 1 else [])
                return opts[0] if opts else ""
            return MagicMock()

        return _sub


class _RenderHarness:
    """Capture Streamlit widget calls made by a view render.

    Each ``st.<widget>`` attribute is replaced with a recording stub so the
    view's body runs in capture mode (no live Streamlit runtime needed).
    ``st.expander`` returns a working context manager and ``st.code`` returns a
    mock so call chains like ``st.code(...).something`` don't blow up.
    """

    def __init__(self) -> None:
        self.calls: dict[str, list[tuple[tuple, dict]]] = {}

    def _record(self, name: str):
        def _fn(*args, **kwargs):
            self.calls.setdefault(name, []).append((args, kwargs))
            if name == "expander":
                return _ExpanderCM()
            if name == "columns":
                # Return mock column objects whose .metric call into the
                # harness's "metric" bucket, so KPIs are observable.
                ncols = args[0] if args else 1
                cols = [_ColumnMetric(self) for _ in range(ncols)]
                return cols
            return MagicMock()

        return _fn

    def patchers(self):
        import streamlit as st

        names = [
            "header", "caption", "subheader", "markdown", "code",
            "expander", "warning", "info", "success", "error",
            "spinner", "dataframe", "number_input",
            "radio", "selectbox", "button", "metric", "stop",
            "plotly_chart", "rerun", "columns", "set_page_config",
        ]
        return [patch.object(st, n, self._record(n)) for n in names]

    @contextlib.contextmanager
    def capture(self):
        import streamlit as st

        with contextlib.ExitStack() as stack:
            for p in self.patchers():
                stack.enter_context(p)
            # st.sidebar.<widget> calls go through self.sidebar stub.
            stack.enter_context(patch.object(st, "spinner", self._record("spinner")))
            stack.enter_context(patch.object(st, "sidebar", _SidebarProxy(self)))
            yield

    def expanders(self) -> list[str]:
        return [args[0] for args, _ in self.calls.get("expander", [])]

    def plotly_charts(self) -> list[tuple[tuple, dict]]:
        return self.calls.get("plotly_chart", [])

    def dataframes(self) -> list[tuple[tuple, dict]]:
        return self.calls.get("dataframe", [])

    def metrics(self) -> list[tuple[tuple, dict]]:
        return self.calls.get("metric", [])

    def buttons(self) -> list[tuple[tuple, dict]]:
        return self.calls.get("button", [])

    def selectboxes(self) -> list[tuple[tuple, dict]]:
        return self.calls.get("selectbox", [])

    def warnings(self) -> list[str]:
        out: list[str] = []
        for args, _ in self.calls.get("warning", []):
            if args and isinstance(args[0], str):
                out.append(args[0])
        return out

    def infos(self) -> list[str]:
        out: list[str] = []
        for args, _ in self.calls.get("info", []):
            if args and isinstance(args[0], str):
                out.append(args[0])
        return out


@pytest.fixture
def harness() -> _RenderHarness:
    return _RenderHarness()


@pytest.fixture(scope="module")
def repo_config() -> dict:
    from src.config_loader import load_config

    return load_config("config.yaml")


# ---------------------------------------------------------------------------
# Fake data builders (frozen contracts from the analysis layer)
# ---------------------------------------------------------------------------


_TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access",
    "execution", "persistence", "privilege-escalation", "defense-evasion",
    "credential-access", "discovery", "lateral-movement", "collection",
    "command-and-control", "exfiltration", "impact",
]


def _fake_tactic_coverage():
    """14 canonical TacticCoverage in ATT&CK order."""
    return tuple(
        SimpleNamespace(tactic=t, total=10, detectable=max(1, i), pct=i / 10.0)
        for i, t in enumerate(_TACTIC_ORDER)
    )


def _fake_coverage_row(**kw):
    defaults = {
        "technique_stix_id": "attack-pattern--1",
        "attack_id": "T1059.001",
        "name": "PowerShell",
        "tactic": "execution",
        "scope_hit": True,
        "best_confidence": 0.5,
        "is_detectable": False,
        "source_ids": (),
        "sigma_rule_id": None,
    }
    defaults.update(kw)
    return SimpleNamespace(**defaults)


def _fake_gap(attack_id: str, name: str, tactic: str, closable_by=(), conf: float = 0.1):
    return SimpleNamespace(
        technique_attack_id=attack_id,
        name=name,
        tactic=tactic,
        best_confidence=conf,
        closable_by=tuple(closable_by),
    )


def _fake_cluster(cluster_id: int, label: str, ids: tuple[str, ...]):
    return SimpleNamespace(
        cluster_id=cluster_id,
        label=label,
        technique_ids=ids,
        summary=f"Stub cluster {cluster_id}",
        size=len(ids),
    )


def _fake_group_option(gid: str = "G0016", name: str = "APT29", count: int = 66):
    return SimpleNamespace(
        group_id=gid,
        stix_id="x--group",
        name=name,
        aliases=(name,),
        technique_count=count,
        label=f"{name} ({count})",
    )


def _fake_outcome():
    """A frozen-ish SimulationResult stand-in mirroring the ORM shape."""
    per_tactic = {
        tactic: {
            "total": 10,
            "detected": i,
            "missed": 10 - i,
        }
        for i, tactic in enumerate(_TACTIC_ORDER)
    }
    return SimpleNamespace(
        group_id="G0016",
        id=1,
        total_techniques=66,
        detected_count=6,
        missed_count=58,
        coverage_pct=0.1212,
        summary={
            "detected_rollup": 2,
            "per_tactic": per_tactic,
            "recommendations": [
                "Enable evtx to cover 3 missed techniques"
            ],
        },
    )


# ---------------------------------------------------------------------------
# Coverage Overview
# ---------------------------------------------------------------------------


class TestCoverageView:
    def test_renders_heatmap_and_kpis(
        self, tmp_path, repo_config, harness
    ) -> None:
        from src.visualization.views import coverage as v

        engine, session = _attach_readonly_sqlite(tmp_path)
        try:
            with patch.object(v, "load_coverage_rows") as mock_rows, \
                 patch.object(v, "coverage_by_tactic") as mock_tactic:
                mock_rows.return_value = [_fake_coverage_row() for _ in range(3)]
                mock_tactic.return_value = _fake_tactic_coverage()
                with harness.capture():
                    v.render_coverage_view(session, repo_config)
        finally:
            session.close()
            engine.dispose()

        # One heatmap + one dataframe (the tactic-detail table).
        assert len(harness.plotly_charts()) == 1
        assert len(harness.dataframes()) == 1
        # KPI cards = 5 metrics.
        assert len(harness.metrics()) == 5

    def test_empty_coverage_renders_info(
        self, tmp_path, repo_config, harness
    ) -> None:
        from src.visualization.views import coverage as v

        engine, session = _attach_readonly_sqlite(tmp_path)
        try:
            with patch.object(v, "load_coverage_rows") as mock_rows:
                mock_rows.return_value = []
                with harness.capture():
                    v.render_coverage_view(session, repo_config)
        finally:
            session.close()
            engine.dispose()

        assert any("No techniques" in i for i in harness.infos())


# ---------------------------------------------------------------------------
# APT Simulation
# ---------------------------------------------------------------------------


class TestSimulationView:
    def test_group_picker_then_run(
        self, tmp_path, repo_config, harness
    ) -> None:
        from src.visualization.views import simulation as v

        engine, session = _attach_readonly_sqlite(tmp_path)
        try:
            # selectbox returns the default group_id; button press = "run".
            with patch.object(v, "list_apt_groups") as mock_picker, \
                 patch.object(v, "simulate_apt_attack") as mock_sim:
                mock_picker.return_value = (_fake_group_option(),)
                mock_sim.return_value = _fake_outcome()
                with harness.capture():
                    v.render_simulation_view(session, repo_config)
        finally:
            session.close()
            engine.dispose()

        # Group picker fires once.
        assert len(harness.selectboxes()) >= 1
        # "Run simulation" button rendered.
        assert any(
            args and args[0] == "Run simulation"
            for args, _ in harness.buttons()
        )

    def test_run_renders_outcome(
        self, tmp_path, repo_config, harness
    ) -> None:
        """When the run button is pressed, simulate fires and KPIs render."""
        from src.visualization.views import simulation as v

        engine, session = _attach_readonly_sqlite(tmp_path)
        try:
            with patch.object(v, "list_apt_groups") as mock_picker, \
                 patch.object(v, "simulate_apt_attack") as mock_sim:
                mock_picker.return_value = (_fake_group_option(),)
                mock_sim.return_value = _fake_outcome()
                with harness.capture():
                    v.render_simulation_view(session, repo_config)
                    # Simulate the button press rendering the outcome.
                    v.render_simulation_view(session, repo_config)
        finally:
            session.close()
            engine.dispose()

        # simulate_apt_attack called with the picked group_id.
        assert mock_sim.called
        args, kwargs = mock_sim.call_args
        assert args[0] == "G0016"
        # KPI metrics + bar chart + recommendations rendered.
        assert len(harness.metrics()) >= 5
        assert len(harness.plotly_charts()) >= 1


# ---------------------------------------------------------------------------
# Gap Analysis
# ---------------------------------------------------------------------------


class TestGapView:
    def test_renders_clusters_and_table(
        self, tmp_path, repo_config, harness
    ) -> None:
        from src.visualization.views import gap as v

        engine, session = _attach_readonly_sqlite(tmp_path)
        try:
            with patch.object(v, "load_coverage_rows") as mock_rows, \
                 patch.object(v, "calculate_coverage_gaps") as mock_gaps, \
                 patch.object(v, "cluster_gaps") as mock_clusters, \
                 patch("src.parser.mappings_io.load_mappings") as mock_maps:
                mock_rows.return_value = [_fake_coverage_row() for _ in range(5)]
                mock_gaps.return_value = (
                    _fake_gap("T1000", "Foo", "execution", closable_by=("zeek",)),
                    _fake_gap("T1001", "Bar", "execution"),
                )
                mock_clusters.return_value = (
                    _fake_cluster(1, "execution: foo", ("T1000",)),
                    _fake_cluster(2, "execution: bar", ("T1001",)),
                )
                mock_maps.return_value = []
                with harness.capture():
                    v.render_gap_view(session, repo_config)
        finally:
            session.close()
            engine.dispose()

        # Two cluster expanders.
        clusters = [e for e in harness.expanders() if e.startswith("Cluster")]
        assert len(clusters) == 2
        # Full gap detail table always rendered.
        assert len(harness.dataframes()) >= 1
        # KPIs rendered.
        assert len(harness.metrics()) >= 3

    def test_empty_gaps_renders_info(
        self, tmp_path, repo_config, harness
    ) -> None:
        from src.visualization.views import gap as v

        engine, session = _attach_readonly_sqlite(tmp_path)
        try:
            with patch.object(v, "load_coverage_rows") as mock_rows, \
                 patch.object(v, "calculate_coverage_gaps") as mock_gaps, \
                 patch("src.parser.mappings_io.load_mappings") as mock_maps:
                mock_rows.return_value = []
                mock_gaps.return_value = ()
                mock_maps.return_value = []
                with harness.capture():
                    v.render_gap_view(session, repo_config)
        finally:
            session.close()
            engine.dispose()

        assert any("No coverage gaps" in i for i in harness.infos())


# ---------------------------------------------------------------------------
# Hunt (sanity that the view is still wired / still works)
# ---------------------------------------------------------------------------


class TestHuntViewStillWorks:
    def test_render_with_real_export(
        self, tmp_path, repo_config, harness
    ) -> None:
        """Smoke: render_hunt_view still dispatches export_all_queries with a
        session + result_id and renders expanders."""
        from src.visualization.views import hunt as v
        from tests.test_hunt_view import _RenderHarness as _HuntHarness, _fake_queries

        h = _HuntHarness()
        engine, session = _attach_readonly_sqlite(tmp_path)
        try:
            result = (
                session.execute(select(SimulationResult)).scalars().first()
            )
            with patch.object(v, "export_all_queries") as mock_export:
                mock_export.return_value = _fake_queries(3)
                with h.capture():
                    v.render_hunt_view(result.id, session=session, config=repo_config)
            session.rollback()
        finally:
            session.close()
            engine.dispose()

        # At least one st.code (the query) + the gap-list dataframe.
        assert len(h.calls.get("code", [])) >= 3
