"""Contract tests for the Anomaly Detection module (Isolation Forest).

Verifies:
1. Feature extraction produces expected shape.
2. Model trains and predicts on synthetic data.
3. Anomaly score ordering (known outlier scores higher / more negative).
4. Persistence round-trip (reloaded model produces same predictions).
5. Empty/null event handling.

Run: PYTHONPATH=src ./.venv/Scripts/python.exe -m pytest tests/test_anomaly_detector.py -q
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pytest

from src.analysis.anomaly_detector import AnomalyDetector
from src.parser.log_event_bridge import LogEvent


def _make_event(
    event_action: str = "logon_failure",
    source_format: str = "evtx",
    timestamp: str = "2026-08-27T10:30:00Z",
    extensions: dict | None = None,
    **kwargs,
) -> LogEvent:
    """Build a LogEvent with sensible defaults for testing."""
    # Use an explicit None check so that extensions={} (empty dict) is not
    # replaced by the default {"event_id": "4625"}.
    ext = extensions if extensions is not None else {"event_id": "4625"}
    return LogEvent(
        event_action=event_action,
        source_format=source_format,
        timestamp=timestamp,
        extensions=ext,
        **kwargs,
    )


class TestFeatureExtraction:
    def test_extract_features_shape(self) -> None:
        events = [_make_event(event_action=f"action_{i}") for i in range(50)]
        det = AnomalyDetector()
        det._build_vocabulary(events)
        X = det.extract_features(events)

        assert X.shape[0] == 50
        assert X.shape[1] == det._feature_dim()
        assert X.dtype == np.float64

    def test_extract_features_empty(self) -> None:
        det = AnomalyDetector()
        X = det.extract_features([])
        assert X.shape == (0, 0)

    def test_extension_count_feature(self) -> None:
        e1 = _make_event(extensions={"a": 1, "b": 2})
        e2 = _make_event(extensions={})
        det = AnomalyDetector()
        det._build_vocabulary([e1, e2])
        X = det.extract_features([e1, e2])

        # extension_count is after all one-hot columns
        n_onehot = len(det._top_actions) + len(det._top_sources)
        assert X[0, n_onehot] == 2.0
        assert X[1, n_onehot] == 0.0

    def test_hour_of_day_feature(self) -> None:
        e = _make_event(timestamp="2026-08-27T15:45:00Z")
        det = AnomalyDetector()
        det._build_vocabulary([e])
        X = det.extract_features([e])

        n_onehot = len(det._top_actions) + len(det._top_sources)
        # hour_of_day is 1 column after extension_count
        assert X[0, n_onehot + 1] == 15.0

    def test_missing_timestamp_defaults_to_zero(self) -> None:
        e = _make_event(timestamp=None)
        det = AnomalyDetector()
        det._build_vocabulary([e])
        X = det.extract_features([e])

        n_onehot = len(det._top_actions) + len(det._top_sources)
        assert X[0, n_onehot + 1] == 0.0  # hour
        assert X[0, n_onehot + 2] == 0.0  # day_of_week


class TestTrainPredict:
    def test_trains_on_synthetic_data(self) -> None:
        events = [_make_event(event_action=f"a{i % 5}") for i in range(100)]
        det = AnomalyDetector()
        det.train(events)
        assert det.model is not None

    def test_predicts_labels(self) -> None:
        events = [_make_event(event_action=f"a{i % 5}") for i in range(100)]
        det = AnomalyDetector(contamination=0.05)
        det.train(events)

        # Predict on same distribution
        preds = det.predict(events)
        assert len(preds) == 100
        labels = [p["label"] for p in preds]
        # With 5% contamination, roughly 5% should be flagged
        n_anomalies = labels.count(-1)
        assert 0 <= n_anomalies <= 20

    def test_outlier_scores_higher(self) -> None:
        # Normal events: slight variation so the forest has signal
        rng = np.random.default_rng(42)
        normal = []
        for _ in range(100):
            e = _make_event(
                event_action="normal",
                extensions={"event_id": "4625", "extra": rng.integers(0, 5)},
            )
            normal.append(e)

        det = AnomalyDetector(contamination=0.05)
        det.train(normal)

        # A clearly different event: never-before-seen action, many extensions,
        # source IP present, process name, large bytes
        outlier = LogEvent(
            event_action="TOTALLY_UNKNOWN_ACTION",
            source_format="unknown_format",
            extensions={f"k{i}": i for i in range(20)},
            source_ip="10.0.0.1",
            process_name="suspicious.exe",
            bytes_in=999999,
            bytes_out=999999,
        )
        test_events = [normal[0], normal[1], outlier]
        preds = det.predict(test_events)

        # The outlier should have the lowest (most anomalous) score.
        # With default IsolationForest scoring, anomalies have more negative scores.
        assert preds[2]["score"] <= preds[0]["score"], (
            f"outlier score {preds[2]['score']} should be <= normal {preds[0]['score']}"
        )

    def test_predict_before_train(self) -> None:
        det = AnomalyDetector()
        events = [_make_event() for _ in range(10)]
        preds = det.predict(events)
        # All normal (label=1), score=0.0
        assert all(p["label"] == 1 and p["score"] == 0.0 for p in preds)


class TestPersistence:
    def test_round_trip(self, tmp_path: Path) -> None:
        events = [_make_event(event_action=f"a{i % 5}") for i in range(100)]
        det = AnomalyDetector()
        det.train(events)

        # Use a path inside the allowed models directory
        path = Path("models") / "test_model.joblib"
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            det.persist(str(path))

            # Reload
            loaded = AnomalyDetector.load(str(path))
            assert loaded.model is not None

            # Same predictions
            test = [_make_event(event_action="a0") for _ in range(5)]
            orig_preds = det.predict(test)
            loaded_preds = loaded.predict(test)

            for a, b in zip(orig_preds, loaded_preds):
                assert a["label"] == b["label"]
                assert abs(a["score"] - b["score"]) < 1e-6
        finally:
            # Clean up
            if path.exists():
                path.unlink()
            sidecar = path.with_suffix(path.suffix + ".sha256")
            if sidecar.exists():
                sidecar.unlink()

    def test_persist_without_model_raises(self) -> None:
        det = AnomalyDetector()
        with pytest.raises(ValueError, match="no trained model"):
            det.persist("models/test_m.joblib")

    def test_path_traversal_rejected(self) -> None:
        det = AnomalyDetector()
        det.train([_make_event() for _ in range(50)])
        with pytest.raises(ValueError, match="escapes allowed directory"):
            det.persist("../../etc/evil.joblib")

    def test_tampered_model_rejected(self) -> None:
        events = [_make_event(event_action=f"a{i % 5}") for i in range(100)]
        det = AnomalyDetector()
        det.train(events)

        path = Path("models") / "tampered_model.joblib"
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            det.persist(str(path))

            # Tamper with the file
            original = path.read_bytes()
            path.write_bytes(original[:-1] + bytes([original[-1] ^ 0xFF]))

            with pytest.raises(ValueError, match="HMAC integrity"):
                AnomalyDetector.load(str(path))
        finally:
            if path.exists():
                path.unlink()
            sidecar = path.with_suffix(path.suffix + ".sha256")
            if sidecar.exists():
                sidecar.unlink()


class TestEmptyNullHandling:
    def test_empty_events_train_raises(self) -> None:
        det = AnomalyDetector()
        with pytest.raises(ValueError, match="empty"):
            det.train([])

    def test_empty_events_predict_returns_empty(self) -> None:
        det = AnomalyDetector()
        assert det.predict([]) == []

    def test_none_fields_handled(self) -> None:
        e = LogEvent()  # all defaults (None/empty)
        det = AnomalyDetector()
        det._build_vocabulary([e])
        X = det.extract_features([e])
        assert X.shape == (1, det._feature_dim())
        # No NaN or inf
        assert not np.any(np.isnan(X))
        assert not np.any(np.isinf(X))
