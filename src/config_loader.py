"""Configuration loader for the ATT&CK Coverage Mapper.

Reads ``config.yaml`` and returns a normalized dict with exactly these keys:

- ``platform_scope`` (str): which platform's techniques are in scope
  (e.g. ``"windows"``); defaults to ``"all"``.
- ``detection_confidence_threshold`` (float): a technique counts as
  detectable only at or above this confidence; defaults to ``0.6``.
- ``enabled_log_sources`` (dict[str, bool]): log format -> enabled flag;
  formats absent from the mapping are treated as enabled downstream, so
  the default enables every known parser format explicitly.
- ``clustering`` (dict[str, int | float]): optional top-level section of
  gap-clustering knobs consumed by ``gap_clustering.py``. Absent keys
  fall back to ``DEFAULT_CLUSTERING``: ``min_clusterable=4`` (attempt
  KMeans only with at least this many gap items), ``k_max=6`` (largest
  tried ``k``), ``silhouette_threshold=0.2`` (minimum mean silhouette to
  accept a partition), ``max_vocab=200`` (TF-IDF vocabulary cap) and
  ``seed=42`` (KMeans/TF-IDF determinism). Integer knobs must be plain
  ints (YAML booleans rejected), ``min_clusterable >= 1``, ``k_max >= 2``
  (silhouette needs two clusters), ``max_vocab >= 1`` and ``seed``
  within ``[0, 2**32 - 1]`` (NumPy RandomState limit);
  ``silhouette_threshold`` accepts any number within ``[-1.0, 1.0]``
  (the silhouette-score domain). Unknown keys inside the section are
  warned about and dropped.

Missing keys fall back to sane defaults; a missing config file raises
``FileNotFoundError`` naturally from ``open()``.
"""

import logging

import yaml

logger = logging.getLogger(__name__)

# Parser formats supported by siem-log-parser; all enabled unless the
# config says otherwise.
_KNOWN_LOG_SOURCES = (
    "evtx",
    "syslog",
    "cef",
    "leef",
    "json",
    "aws_cloudtrail",
    "nginx",
    "zeek",
)

# Largest accepted ``seed``: NumPy's RandomState rejects anything above
# 2**32 - 1, so the loader does the same up front.
_SEED_MAX = 2**32 - 1

# Defaults for the optional top-level ``clustering`` section (Phase-3 gap
# clustering): cluster only with >= min_clusterable gap items, search
# k in [2, k_max], accept a partition at mean silhouette >=
# silhouette_threshold, cap the TF-IDF vocabulary at max_vocab tokens,
# and pin everything to ``seed`` for byte-identical reruns.
DEFAULT_CLUSTERING: dict[str, int | float] = {
    "min_clusterable": 4,
    "k_max": 6,
    "silhouette_threshold": 0.2,
    "max_vocab": 200,
    "seed": 42,
}

# Type for collected_log_sources: None = unknown (key absent or null),
# frozenset() = explicitly empty, frozenset([...]) = declared inventory.
CollectedSources = frozenset[str] | None

DEFAULT_CONFIG: dict[str, object] = {
    "platform_scope": "all",
    "detection_confidence_threshold": 0.6,
    "enabled_log_sources": {fmt: True for fmt in _KNOWN_LOG_SOURCES},
    "collected_log_sources": None,
    # Registered here so load_config's unknown-top-level-key warning does
    # not fire on ``clustering``; normalization always copies fresh.
    "clustering": dict(DEFAULT_CLUSTERING),
}


def _normalize_platform_scope(value: object) -> str:
    """Return a validated ``platform_scope`` string."""
    if value is None:
        return str(DEFAULT_CONFIG["platform_scope"])
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"config 'platform_scope' must be a non-empty string, got {value!r}"
        )
    return value


def _normalize_threshold(value: object) -> float:
    """Return a validated ``detection_confidence_threshold`` float in [0.0, 1.0]."""
    if value is None:
        return float(DEFAULT_CONFIG["detection_confidence_threshold"])  # type: ignore[arg-type]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(
            "config 'detection_confidence_threshold' must be a number, "
            f"got {value!r}"
        )
    threshold = float(value)
    if not 0.0 <= threshold <= 1.0:
        raise ValueError(
            f"config 'detection_confidence_threshold' must be within [0.0, 1.0], got {threshold}"
        )
    return threshold


def _normalize_enabled_log_sources(value: object) -> dict[str, bool]:
    """Return a validated ``enabled_log_sources`` mapping of format name to bool."""
    if value is None:
        sources = DEFAULT_CONFIG["enabled_log_sources"]
        assert isinstance(sources, dict)
        return dict(sources)
    if not isinstance(value, dict):
        raise ValueError(
            f"config 'enabled_log_sources' must be a mapping of format name to bool, got {value!r}"
        )
    return {str(fmt).lower(): bool(enabled) for fmt, enabled in value.items()}


def _normalize_collected_log_sources(value: object) -> CollectedSources:
    """Return a validated ``collected_log_sources`` value.

    Semantics:
    - ``None`` (key absent or ``null``) → inventory unknown.
    - Empty list ``[]`` → inventory explicitly empty.
    - Non-empty list → declared inventory as ``frozenset`` of source names.
    """
    if value is None:
        return None
    if not isinstance(value, (list, tuple)):
        raise ValueError(
            f"config 'collected_log_sources' must be a list or null, got {type(value).__name__}"
        )
    return frozenset(str(fmt).lower() for fmt in value)


def _require_int_in_range(
    key: str, raw: object, minimum: int, maximum: int | None
) -> int:
    """Return *raw* as an ``int`` within bounds or raise ``ValueError``.

    Booleans are rejected even though ``bool`` subclasses ``int``: a YAML
    ``true``/``false`` must never silently become the knob values 1/0.
    ``maximum=None`` means "no upper bound".
    """
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise ValueError(f"config 'clustering.{key}' must be an integer, got {raw!r}")
    if raw < minimum or (maximum is not None and raw > maximum):
        bound = f"[{minimum}, {maximum}]" if maximum is not None else f">= {minimum}"
        raise ValueError(
            f"config 'clustering.{key}' must be within {bound}, got {raw}"
        )
    return raw


def _require_float_in_range(
    key: str, raw: object, minimum: float, maximum: float
) -> float:
    """Return *raw* as a ``float`` within ``[minimum, maximum]`` or raise."""
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise ValueError(f"config 'clustering.{key}' must be a number, got {raw!r}")
    value = float(raw)
    if not minimum <= value <= maximum:
        raise ValueError(
            f"config 'clustering.{key}' must be within "
            f"[{minimum}, {maximum}], got {value}"
        )
    return value


def _normalize_clustering(value: object) -> dict[str, int | float]:
    """Return a fully populated ``clustering`` section.

    Args:
        value: Raw ``clustering`` node from the YAML document. ``None``
            (key absent, or explicitly written as ``clustering: null``)
            selects the complete default set; anything else must be a
            mapping whose per-key ``None`` entries fall back to that
            key's default.

    Returns:
        A fresh dict holding exactly the documented knobs
        (``min_clusterable``, ``k_max``, ``silhouette_threshold``,
        ``max_vocab``, ``seed``). Unlike unknown top-level keys, unknown
        keys inside this fixed-schema section are logged at WARNING and
        dropped rather than preserved. Callers may mutate the returned
        dict freely; module-level defaults are copied, never shared.

    Raises:
        ValueError: If *value* is neither ``None`` nor a mapping, or if
            any known knob violates its type/range contract (see module
            docstring for the exact bounds).
    """
    if value is None:
        return dict(DEFAULT_CLUSTERING)
    if not isinstance(value, dict):
        raise ValueError(
            "config 'clustering' must be a mapping of knob name to number, "
            f"got {type(value).__name__}: {value!r}"
        )

    unknown = set(value) - set(DEFAULT_CLUSTERING)
    if unknown:
        logger.warning(
            "Ignoring unknown keys in config 'clustering': %s", sorted(unknown)
        )

    def _with_default(key: str) -> object:
        """Substitute the section default for missing/null entries."""
        raw = value.get(key)
        return DEFAULT_CLUSTERING[key] if raw is None else raw

    return {
        "min_clusterable": _require_int_in_range(
            "min_clusterable", _with_default("min_clusterable"), minimum=1, maximum=None
        ),
        "k_max": _require_int_in_range(
            "k_max", _with_default("k_max"), minimum=2, maximum=None
        ),
        "silhouette_threshold": _require_float_in_range(
            "silhouette_threshold",
            _with_default("silhouette_threshold"),
            minimum=-1.0,
            maximum=1.0,
        ),
        "max_vocab": _require_int_in_range(
            "max_vocab", _with_default("max_vocab"), minimum=1, maximum=None
        ),
        "seed": _require_int_in_range(
            "seed", _with_default("seed"), minimum=0, maximum=_SEED_MAX
        ),
    }


def load_config(path: str = "config.yaml") -> dict[str, object]:
    """Load and normalize the application configuration from a YAML file.

    Args:
        path: Path to the YAML configuration file. Defaults to
            ``config.yaml`` relative to the current working directory.

    Returns:
        A dict with at least the keys ``platform_scope`` (str),
        ``detection_confidence_threshold`` (float),
        ``enabled_log_sources`` (dict[str, bool]),
        ``collected_log_sources`` (frozenset[str] | None) and ``clustering``
        (dict[str, int | float], always fully populated from
        ``DEFAULT_CLUSTERING`` when the file omits or nulls the
        section). Unknown extra keys present in the file are preserved
        as-is. Missing keys are filled with defaults; a missing file
        raises ``FileNotFoundError``.

        ``collected_log_sources`` semantics:
        - ``None`` (key absent or ``null``) → inventory unknown.
        - ``frozenset()`` (empty list in YAML) → inventory explicitly empty.
        - ``frozenset([...])`` → declared inventory.

    Raises:
        FileNotFoundError: If ``path`` does not exist.
        ValueError: If the YAML root is not a mapping or any known key
            has an invalid value (including any ``clustering`` knob).
    """
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    if data is None:
        logger.warning("Config file %s is empty; using full defaults", path)
        data = {}
    if not isinstance(data, dict):
        raise ValueError(
            f"Config file {path} must contain a YAML mapping, got {type(data).__name__}"
        )

    unknown = set(data) - set(DEFAULT_CONFIG)
    if unknown:
        logger.warning("Ignoring unknown config keys in %s: %s", path, sorted(unknown))

    config: dict[str, object] = {
        **data,
        "platform_scope": _normalize_platform_scope(data.get("platform_scope")),
        "detection_confidence_threshold": _normalize_threshold(
            data.get("detection_confidence_threshold")
        ),
        "enabled_log_sources": _normalize_enabled_log_sources(
            data.get("enabled_log_sources")
        ),
        "collected_log_sources": _normalize_collected_log_sources(
            data.get("collected_log_sources")
        ),
        "clustering": _normalize_clustering(data.get("clustering")),
    }
    logger.debug(
        "Loaded config from %s: platform_scope=%r threshold=%r sources=%r collected=%r clustering=%r",
        path,
        config["platform_scope"],
        config["detection_confidence_threshold"],
        config["enabled_log_sources"],
        config["collected_log_sources"],
        config["clustering"],
    )
    return config
