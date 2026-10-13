"""Sigma conversion cache (Phase 5 Wave 2 -- hunt-query generator support).

pySigma's :class:`~sigma.backends.splunk.SplunkBackend.convert_rule` is
deterministic for a fixed (rule, backend, pipeline) triple, so its output is
safe to memoize on disk. This module owns the JSON cache at
``data/cache/sigma_conversions.json`` keyed by the SHA-256 of the raw rule
YAML plus the backend and pipeline names -- any change in the rule text, the
backend, or the processing pipeline produces a different key, so the cache
self-invalidates on SigmaHQ HEAD change (the cloned rule files change) or on
a pySigma/pipeline upgrade.

The cache is a pure dict persisted as JSON; it is NOT a SQLAlchemy model and
lives outside the DB so it can be carried in a SigmaHQ clone's ``.gitignore``
footprint without polluting ``db/coverage.db``. Reads and writes are process-
local (this tool is single-process); concurrent writers are out of scope.

Cache key contract (Wave 1, research/p5-wave1-full-results.md):
    (sha256(raw_yaml), backend_name, pipeline_name)

where ``raw_yaml`` is the exact rule file bytes (so a whitespace or comment
edit invalidates), ``backend_name`` is the Splunk backend class name, and
``pipeline_name`` is the pipeline class name. The stored value is the list of
converted query strings (:class:`SplunkBackend.convert_rule` returns
``list[str]``).
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Iterable

logger = logging.getLogger(__name__)

__all__ = (
    "CACHE_PATH",
    "SigmaConversionCache",
    "cache_key",
    "load_cache",
    "save_cache",
)

#: On-disk location of the conversion cache. Lives under ``data/cache/`` which
#: is git-ignored (see ``.gitignore``); the directory is created on first write.
CACHE_PATH = Path("data/cache/sigma_conversions.json")


def _ensure_cache_dir(path: Path) -> None:
    """Create the cache's parent directory if absent (idempotent)."""
    parent = path.parent
    if str(parent) not in ("", "."):
        parent.mkdir(parents=True, exist_ok=True)


def cache_key(raw_yaml: str, backend_name: str, pipeline_name: str) -> str:
    """Build the deterministic cache key for one conversion.

    The key embeds the SHA-256 of the raw YAML so any edit to the rule file
    (including whitespace/comments) invalidates the entry, plus the backend
    and pipeline names so a pySigma or pipeline upgrade also invalidates.

    Args:
        raw_yaml: The exact rule file text (as ``Path.read_text()`` returns).
        backend_name: Backend class name (e.g. ``"SplunkBackend"``).
        pipeline_name: Pipeline class name (e.g. ``"splunk_windows_pipeline"``
            -- the callable's ``__name__``, not the instance type).

    Returns:
        A string key of the form ``"<sha256>:<backend>:<pipeline>"``.
    """
    digest = hashlib.sha256(raw_yaml.encode("utf-8")).hexdigest()
    return f"{digest}:{backend_name}:{pipeline_name}"


def load_cache(path: Path = CACHE_PATH) -> dict[str, list[str]]:
    """Load the conversion cache from disk.

    Missing or corrupt cache files are treated as empty (the conversion is
    simply recomputed and the cache rewritten); a corrupt file is logged at
    WARNING so a recurring parse error is visible.

    Args:
        path: JSON file path (defaults to ``CACHE_PATH``).

    Returns:
        Mapping of cache key -> list of converted query strings. Returns an
        empty dict when the file is absent or unreadable.
    """
    if not path.is_file():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as err:
        logger.warning("sigma cache corrupt/unreadable (%s); starting empty", err)
        return {}
    if not isinstance(data, dict):
        logger.warning("sigma cache root is not a dict; starting empty")
        return {}
    # Defensive copy: every value must be a list of strings.
    clean: dict[str, list[str]] = {}
    for key, value in data.items():
        if isinstance(value, list) and all(isinstance(v, str) for v in value):
            clean[str(key)] = [str(v) for v in value]
        else:
            logger.debug("sigma cache: skipping malformed entry %r", key)
    return clean


def save_cache(cache: Mapping[str, Iterable[str]], path: Path = CACHE_PATH) -> None:
    """Persist the conversion cache to disk atomically.

    Writes to a temporary file then renames, so a crash mid-write cannot
    corrupt the existing cache (rename is atomic on the same filesystem on
    all supported OSes). The parent directory is created if needed.

    Args:
        cache: Mapping of cache key -> converted query strings.
        path: JSON file path (defaults to ``CACHE_PATH``).
    """
    _ensure_cache_dir(path)
    tmp = path.with_suffix(path.suffix + ".tmp")
    payload = {str(key): [str(v) for v in value] for key, value in cache.items()}
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
        fh.write("\n")
    tmp.replace(path)
    logger.debug("sigma cache saved: %d entries -> %s", len(payload), path)


class SigmaConversionCache:
    """In-memory view of the on-disk conversion cache with write-through.

    Wraps a plain dict loaded from :func:`load_cache` and writes it back via
    :func:`save_cache` on :meth:`commit`. Lookups are synchronous; writes are
    buffered in memory until :meth:`commit` persists them. This keeps the
    hunt-query generator's hot path (one lookup per candidate rule) free of
    file I/O while guaranteeing durability once a batch finishes.

    Attributes:
        _cache: The live mapping (never ``None``).
        _path: The on-disk path committed to.
        _dirty: Whether the in-memory map has uncommitted changes.
    """

    def __init__(
        self,
        path: Path = CACHE_PATH,
        initial: Mapping[str, Iterable[str]] | None = None,
    ) -> None:
        """Load the cache from disk, overlaying ``initial`` if provided.

        Args:
            path: On-disk JSON path.
            initial: Optional seed mapping used when the on-disk cache is
                absent (tests inject deterministic fixtures this way).
        """
        self._path = path
        self._dirty = False
        loaded = load_cache(path)
        if initial is not None:
            for key, value in initial.items():
                loaded[str(key)] = [str(v) for v in value]
            self._dirty = True
        self._cache: dict[str, list[str]] = loaded

    def lookup(self, raw_yaml: str, backend_name: str, pipeline_name: str) -> list[str] | None:
        """Return the cached conversion, or ``None`` if absent.

        Args:
            raw_yaml: Exact rule file text.
            backend_name: Backend class name.
            pipeline_name: Pipeline callable name.

        Returns:
            The cached query strings, or ``None`` on a miss.
        """
        key = cache_key(raw_yaml, backend_name, pipeline_name)
        value = self._cache.get(key)
        if value is None:
            return None
        # Return a copy so callers cannot mutate our internal list.
        return list(value)

    def store(
        self,
        raw_yaml: str,
        backend_name: str,
        pipeline_name: str,
        queries: Iterable[str],
    ) -> None:
        """Buffer a conversion result in memory (persisted on :meth:`commit`).

        Args:
            raw_yaml: Exact rule file text.
            backend_name: Backend class name.
            pipeline_name: Pipeline callable name.
            queries: Converted query strings to cache.
        """
        key = cache_key(raw_yaml, backend_name, pipeline_name)
        self._cache[key] = [str(q) for q in queries]
        self._dirty = True

    def commit(self) -> None:
        """Write the cache to disk if it has unwritten changes.

        A no-op when nothing has been stored since load/last commit, so callers
        may call this unconditionally at the end of a batch.
        """
        if not self._dirty:
            return
        save_cache(self._cache, self._path)
        self._dirty = False

    def __len__(self) -> int:
        return len(self._cache)

    def __contains__(self, item: str) -> bool:
        return item in self._cache
