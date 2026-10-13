"""Contract tests for the Anomaly Detection Streamlit view.

Verifies the frozen view contract:
1. Metric cards: total events, anomaly count, anomaly rate.
2. Dataframe of events + anomaly score is rendered.
3. Bar chart of anomaly scores is rendered.
4. Toggle (show-only-anomalies checkbox) is wired.

Streamlit is mocked so these run offline with no browser.
"""

from __future__ import annotations

import contextlib
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import streamlit as st

from src.visualization.views import anomaly as anomaly_view


class _ExpanderCM:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None


class _ColumnMetric:
    def __init__(self, harness: "_RenderHarness") -> None:
        self._h = harness

    def metric(self, *args, **kwargs):
        self._h.calls.setdefault("metric", []).append((args, kwargs))
        return MagicMock()


class _RenderHarness:
    def __init__(self) -> None:
        self.calls: dict[str, list[tuple[tuple, dict]]] = {}

    def _record(self, name: str):
        def _fn(*args, **kwargs):
            self.calls.setdefault(name, []).append((args, kwargs))
            if name == "expander":
                return _ExpanderCM()
            if name == "columns":
                ncols = args[0] if args else 1
                return [_ColumnMetric(self) for _ in range(ncols)]
            return MagicMock()

        return _fn

    def patchers(self):
        names = [
            "header", "caption", "subheader", "markdown", "code",
            "expander", "warning", "info", "success", "error",
            "spinner", "dataframe", "checkbox",
            "radio", "selectbox", "button", "metric", "stop",
            "plotly_chart", "rerun", "columns", "set_page_config",
        ]
        return [patch.object(st, n, self._record(n)) for n in names]

    @contextlib.contextmanager
    def capture(self):
        with contextlib.ExitStack() as stack:
            for p in self.patchers():
                stack.enter_context(p)
            stack.enter_context(patch.object(st, "spinner", self._record("spinner")))
            yield

    def metrics(self) -> list[tuple[tuple, dict]]:
        return self.calls.get("metric", [])

    def dataframes(self) -> list[tuple[tuple, dict]]:
        return self.calls.get("dataframe", [])

    def plotly_charts(self) -> list[tuple[tuple, dict]]:
        return self.calls.get("plotly_chart", [])

    def checkboxes(self) -> list[tuple[tuple, dict]]:
        return self.calls.get("checkbox", [])


@pytest.fixture
def harness():
    return _RenderHarness()


@pytest.fixture
def repo_config():
    from src.config_loader import load_config

    return load_config("config.yaml")


class TestAnomalyView:
    def test_renders_metrics_dataframe_and_chart(
        self, harness, repo_config
    ) -> None:
        with harness.capture():
            anomaly_view.render_anomaly_view(config=repo_config)

        # 3 metric cards
        assert len(harness.metrics()) == 3
        # 1 dataframe
        assert len(harness.dataframes()) == 1
        # 1 plotly chart
        assert len(harness.plotly_charts()) == 1
        # 1 checkbox toggle
        assert len(harness.checkboxes()) == 1

    def test_demo_events_are_generated(self) -> None:
        events = anomaly_view._demo_events(200)
        assert len(events) == 200
        # Last 5 are the injected anomalies
        assert all(
            e.event_action.startswith("rare_action_") for e in events[-5:]
        )
        # The rest are normal
        assert all(e.event_action == "logon_failure" for e in events[:-5])
