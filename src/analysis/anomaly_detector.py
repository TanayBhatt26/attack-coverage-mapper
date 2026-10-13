"""Anomaly Detection module (Isolation Forest over parsed LogEvents).

Trains an Isolation Forest on feature vectors extracted from normalized
LogEvent objects and flags events that deviate from the learned "normal"
pattern. The model is persisted via joblib and retrainable when the event
volume exceeds a configurable threshold.

Feature vector per event (all numeric):
  - event_action: one-hot encoded (top-K frequent actions from training)
  - source_format: one-hot encoded
  - extension_count: numeric (len(extensions))
  - hour_of_day: numeric (0-23, from timestamp)
  - day_of_week: numeric (0-6, from timestamp)
  - has_source_ip: binary
  - has_dest_ip: binary
  - has_username: binary
  - has_process_name: binary
  - has_message: binary
  - bytes_in: numeric (0 if None)
  - bytes_out: numeric (0 if None)

Config (config.yaml):
  anomaly_detection:
    enabled: true
    contamination: 0.05
    retrain_threshold: 1000
    random_state: 42
    model_path: models/isolation_forest.joblib
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from src.parser.log_event_bridge import LogEvent

# Secret key used to HMAC-sign persisted model files. In production, inject
# via environment variable; a deterministic fallback is provided for dev so
# the feature works out-of-the-box without configuration.
_MODEL_HMAC_KEY = os.environ.get(
    "ANOMALY_MODEL_HMAC_KEY", "attack-coverage-mapper-dev-key-change-in-prod"
).encode("utf-8")

# Allowed base directory for model files. Paths outside this directory are
# rejected to prevent path traversal via config-supplied model_path.
_ALLOWED_MODEL_DIR = Path("models").resolve()

logger = logging.getLogger(__name__)

# Number of top event_action categories to one-hot encode.
# Keeps the feature matrix bounded even with many distinct actions.
_TOP_ACTIONS_K = 20

# Number of top source_format categories to one-hot encode.
_TOP_SOURCES_K = 10


class AnomalyDetector:
    """Isolation Forest anomaly detector for parsed LogEvents.

    Wraps sklearn's IsolationForest with feature extraction, persistence,
    and a retrain-on-threshold policy.
    """

    def __init__(
        self,
        contamination: float = 0.05,
        random_state: int = 42,
        model_path: str = "models/isolation_forest.joblib",
        retrain_threshold: int = 1000,
    ) -> None:
        self.contamination = contamination
        self.random_state = random_state
        self.model_path = Path(model_path)
        self.retrain_threshold = retrain_threshold
        self.model: Optional[IsolationForest] = None
        self._top_actions: list[str] = []
        self._top_sources: list[str] = []
        self._events_since_train: int = 0

    # ------------------------------------------------------------------
    # Feature extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_hour(ts: Optional[str]) -> int:
        """Extract hour_of_day from an ISO-8601 timestamp string.

        Returns 0 when the timestamp is missing or unparseable.
        """
        if not ts:
            return 0
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return dt.hour
        except (ValueError, TypeError):
            return 0

    @staticmethod
    def _parse_day_of_week(ts: Optional[str]) -> int:
        """Extract day_of_week (0=Monday) from an ISO-8601 timestamp string.

        Returns 0 when the timestamp is missing or unparseable.
        """
        if not ts:
            return 0
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return dt.weekday()
        except (ValueError, TypeError):
            return 0

    def _build_vocabulary(self, events: list[LogEvent]) -> None:
        """Learn the top-K event_action and source_format values from data."""
        from collections import Counter

        action_counts = Counter(e.event_action for e in events if e.event_action)
        self._top_actions = [a for a, _ in action_counts.most_common(_TOP_ACTIONS_K)]

        source_counts = Counter(e.source_format for e in events if e.source_format)
        self._top_sources = [s for s, _ in source_counts.most_common(_TOP_SOURCES_K)]

    def extract_features(self, events: list[LogEvent]) -> np.ndarray:
        """Build the numeric feature matrix for a list of LogEvents.

        Args:
            events: Parsed LogEvent objects.

        Returns:
            A float64 ndarray of shape (n_events, n_features).
            When no vocabulary has been built (model not trained), returns
            an ndarray with 0 columns.
        """
        if not events:
            dim = self._feature_dim() if self._top_actions or self._top_sources else 0
            return np.zeros((0, dim), dtype=np.float64)

        rows: list[list[float]] = []
        for e in events:
            row: list[float] = []

            # event_action one-hot
            for action in self._top_actions:
                row.append(1.0 if e.event_action == action else 0.0)

            # source_format one-hot
            for source in self._top_sources:
                row.append(1.0 if e.source_format == source else 0.0)

            # numeric features
            row.append(float(len(e.extensions)))
            row.append(float(self._parse_hour(e.timestamp)))
            row.append(float(self._parse_day_of_week(e.timestamp)))

            # binary presence flags
            row.append(1.0 if e.source_ip else 0.0)
            row.append(1.0 if e.dest_ip else 0.0)
            row.append(1.0 if e.username else 0.0)
            row.append(1.0 if e.process_name else 0.0)
            row.append(1.0 if e.message else 0.0)

            # numeric payload
            row.append(float(e.bytes_in or 0))
            row.append(float(e.bytes_out or 0))

            rows.append(row)

        return np.array(rows, dtype=np.float64)

    def _feature_dim(self) -> int:
        """Total feature dimension given the current vocabulary."""
        return (
            len(self._top_actions)
            + len(self._top_sources)
            + 3  # extension_count, hour_of_day, day_of_week
            + 5  # binary flags
            + 2  # bytes_in, bytes_out
        )

    # ------------------------------------------------------------------
    # Train / predict
    # ------------------------------------------------------------------

    def train(self, events: list[LogEvent]) -> "AnomalyDetector":
        """Fit the Isolation Forest on the given events.

        Builds the action/format vocabulary from the data, extracts features,
        and trains the model. Returns self for chaining.

        Args:
            events: Parsed LogEvent objects to learn "normal" from.

        Returns:
            self
        """
        if not events:
            raise ValueError("cannot train on empty event list")

        self._build_vocabulary(events)
        X = self.extract_features(events)

        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state,
            n_estimators=100,
        )
        self.model.fit(X)
        self._events_since_train = 0
        logger.info(
            "AnomalyDetector trained on %d events (%d features)",
            len(events),
            X.shape[1],
        )
        return self

    def predict(self, events: list[LogEvent]) -> list[dict[str, Any]]:
        """Predict anomaly labels and scores for events.

        Returns one dict per event:
          {"label": -1 (anomaly) or 1 (normal), "score": float}

        The score is the anomaly score from the Isolation Forest (negative =
        more anomalous). If the model has not been trained, every event is
        returned as normal with score 0.0.

        Args:
            events: Parsed LogEvent objects to score.

        Returns:
            List of {"label": int, "score": float} dicts.
        """
        if self.model is None or not events:
            return [{"label": 1, "score": 0.0} for _ in events]

        X = self.extract_features(events)
        labels = self.model.predict(X).tolist()
        scores = self.model.score_samples(X).tolist()

        self._events_since_train += len(events)

        return [
            {"label": int(label), "score": float(score)}
            for label, score in zip(labels, scores)
        ]

    def should_retrain(self) -> bool:
        """True if enough new events have arrived to trigger a retrain."""
        return self._events_since_train >= self.retrain_threshold

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _resolve_model_path(self, path: Optional[str] = None) -> Path:
        """Resolve and validate a model file path.

        Rejects paths that escape the allowed models directory to prevent
        path traversal via config-supplied model_path.

        Args:
            path: Override path. Defaults to self.model_path.

        Returns:
            A resolved Path within _ALLOWED_MODEL_DIR.

        Raises:
            ValueError: If the path escapes the allowed directory.
        """
        target = Path(path) if path else self.model_path
        target = target.resolve()

        # Path traversal guard: resolved path must be inside allowed dir
        if not str(target).startswith(str(_ALLOWED_MODEL_DIR)):
            raise ValueError(
                f"model path {target} escapes allowed directory {_ALLOWED_MODEL_DIR}"
            )
        return target

    def persist(self, path: Optional[str] = None) -> None:
        """Serialize the trained model (and vocabulary) to joblib.

        Writes atomically (temp file + rename) to avoid partial-write races,
        then writes a sidecar .sha256 HMAC file for integrity verification.

        Args:
            path: Override path. Defaults to self.model_path.
        """
        if self.model is None:
            raise ValueError("no trained model to persist")

        target = self._resolve_model_path(path)
        target.parent.mkdir(parents=True, exist_ok=True)

        payload = {
            "model": self.model,
            "top_actions": self._top_actions,
            "top_sources": self._top_sources,
            "contamination": self.contamination,
            "random_state": self.random_state,
            "retrain_threshold": self.retrain_threshold,
        }

        # Atomic write: write to temp file, then rename
        fd, tmp_path = tempfile.mkstemp(
            dir=target.parent, suffix=".joblib.tmp"
        )
        try:
            os.close(fd)
            joblib.dump(payload, tmp_path)
            os.replace(tmp_path, target)
            # Restrictive permissions (owner read/write only)
            target.chmod(0o600)
        except Exception:
            # Clean up temp file on failure
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise

        # Write HMAC sidecar for integrity verification
        mac = hmac.new(_MODEL_HMAC_KEY, target.read_bytes(), hashlib.sha256)
        sidecar = target.with_suffix(target.suffix + ".sha256")
        sidecar.write_text(mac.hexdigest())

        logger.info("AnomalyDetector persisted to %s", target)

    @classmethod
    def load(cls, path: str = "models/isolation_forest.joblib") -> "AnomalyDetector":
        """Load a persisted detector from joblib.

        Verifies file integrity via the sidecar .sha256 HMAC file before
        deserialization. Validates payload structure and types after loading.

        Args:
            path: Path to the joblib file.

        Returns:
            A restored AnomalyDetector with the trained model.

        Raises:
            ValueError: If the path is outside the allowed directory, the HMAC
                verification fails, or the payload structure is invalid.
        """
        target = cls._resolve_model_path_static(path)

        # Integrity verification before deserialization
        sidecar = target.with_suffix(target.suffix + ".sha256")
        if sidecar.exists():
            expected_mac = sidecar.read_text().strip()
            actual_mac = hmac.new(
                _MODEL_HMAC_KEY, target.read_bytes(), hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(expected_mac, actual_mac):
                raise ValueError(
                    f"model file {target} failed HMAC integrity check — "
                    "file may have been tampered with"
                )
        else:
            logger.warning(
                "No HMAC sidecar found for %s — skipping integrity check",
                target,
            )

        payload = joblib.load(target)

        # Validate payload structure
        if not isinstance(payload, dict):
            raise ValueError(f"expected dict payload, got {type(payload).__name__}")
        required_keys = {
            "model", "top_actions", "top_sources",
            "contamination", "random_state", "retrain_threshold",
        }
        missing = required_keys - set(payload)
        if missing:
            raise ValueError(f"payload missing keys: {missing}")
        if not isinstance(payload["model"], IsolationForest):
            raise ValueError(
                f"expected IsolationForest, got {type(payload['model']).__name__}"
            )
        if not isinstance(payload["top_actions"], list) or not all(
            isinstance(x, str) for x in payload["top_actions"]
        ):
            raise ValueError("top_actions must be a list of strings")
        if not isinstance(payload["top_sources"], list) or not all(
            isinstance(x, str) for x in payload["top_sources"]
        ):
            raise ValueError("top_sources must be a list of strings")

        inst = cls(
            contamination=float(payload["contamination"]),
            random_state=int(payload["random_state"]),
            model_path=path,
            retrain_threshold=int(payload["retrain_threshold"]),
        )
        inst.model = payload["model"]
        inst._top_actions = payload["top_actions"]
        inst._top_sources = payload["top_sources"]
        return inst

    @staticmethod
    def _resolve_model_path_static(path: str) -> Path:
        """Static version of _resolve_model_path for use in load()."""
        target = Path(path).resolve()
        if not str(target).startswith(str(_ALLOWED_MODEL_DIR)):
            raise ValueError(
                f"model path {target} escapes allowed directory {_ALLOWED_MODEL_DIR}"
            )
        return target
