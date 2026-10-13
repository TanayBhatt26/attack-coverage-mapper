"""Tests for ``config_loader.load_config`` (shared Phase-2 interface contract).

The documented surface under test:

* ``load_config(path="config.yaml") -> dict`` exposing the keys
  ``platform_scope`` (str), ``detection_confidence_threshold`` (float) and
  ``enabled_log_sources`` (dict of format name -> bool).
* Sane defaults fill in absent top-level keys; the confidence threshold
  defaults to 0.6 per the project spec (config.yaml comment + dashboard).
* A missing file raises ``FileNotFoundError`` naturally (no swallowing).
* Malformed documents never yield a silently wrong config: syntactically
  broken YAML raises, and non-mapping documents are either rejected or
  normalised into the documented mapping shape.
"""
import logging
from pathlib import Path

import pytest
import yaml

from config_loader import load_config

logger = logging.getLogger(__name__)

# Every test here touches the filesystem (tmp_path fixtures or chdir),
# which pyproject.toml classifies as "integration".
pytestmark = pytest.mark.integration

REQUIRED_KEYS = frozenset(
    {"platform_scope", "detection_confidence_threshold", "enabled_log_sources"}
)

REPO_ROOT = Path(__file__).resolve().parents[1]

# Mirrors the shipped repo config.yaml.
FULL_CONFIG = """\
platform_scope: windows
detection_confidence_threshold: 0.6
enabled_log_sources:
  evtx: true
  syslog: true
  cef: false
  leef: false
  json: true
  aws_cloudtrail: true
  nginx: false
  zeek: true
"""


def _write_config(tmp_path: Path, text: str) -> Path:
    """Write *text* as config.yaml under tmp_path and return its path."""
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    logger.debug("wrote fixture config to %s", path)
    return path


def _assert_rejected_or_normalized(path: str) -> None:
    """Enforce the contract for a non-mapping YAML document.

    A conforming ``load_config`` either refuses the document outright
    (ValueError/TypeError) or normalises it into a dict that carries the
    three required keys. Returning raw non-dict data would violate the
    annotated ``-> dict`` return type.
    """
    try:
        cfg = load_config(path)
    except (ValueError, TypeError):
        return
    assert isinstance(cfg, dict), f"expected dict, got {type(cfg).__name__}"
    missing = REQUIRED_KEYS.difference(cfg)
    assert not missing, f"normalised config lacks required keys: {sorted(missing)}"


def test_full_config_roundtrip(tmp_path: Path) -> None:
    """A fully specified config loads verbatim into the documented keys."""
    cfg = load_config(str(_write_config(tmp_path, FULL_CONFIG)))
    assert isinstance(cfg, dict)
    assert cfg["platform_scope"] == "windows"
    assert cfg["detection_confidence_threshold"] == 0.6
    assert cfg["enabled_log_sources"] == {
        "evtx": True,
        "syslog": True,
        "cef": False,
        "leef": False,
        "json": True,
        "aws_cloudtrail": True,
        "nginx": False,
        "zeek": True,
    }


def test_missing_file_raises_filenotfounderror(tmp_path: Path) -> None:
    """An absent path surfaces FileNotFoundError instead of silent defaults."""
    missing = tmp_path / "does_not_exist.yaml"
    with pytest.raises(FileNotFoundError):
        load_config(str(missing))


def test_partial_config_gets_sane_defaults(tmp_path: Path) -> None:
    """Provided keys win; absent keys fall back to sane defaults."""
    cfg = load_config(str(_write_config(tmp_path, "platform_scope: linux\n")))
    assert REQUIRED_KEYS.issubset(cfg)
    assert cfg["platform_scope"] == "linux"
    # Project-spec default threshold (config.yaml comment, dashboard slider).
    assert cfg["detection_confidence_threshold"] == 0.6
    assert isinstance(cfg["enabled_log_sources"], dict)


def test_empty_file_yields_defaults(tmp_path: Path) -> None:
    """An empty YAML document (parses to None) still yields the full shape."""
    cfg = load_config(str(_write_config(tmp_path, "")))
    assert REQUIRED_KEYS.issubset(cfg)
    assert cfg["detection_confidence_threshold"] == 0.6
    assert isinstance(cfg["enabled_log_sources"], dict)


def test_threshold_is_read_not_hardcoded(tmp_path: Path) -> None:
    """A non-default threshold passes through unchanged."""
    text = "detection_confidence_threshold: 0.85\n"
    cfg = load_config(str(_write_config(tmp_path, text)))
    assert cfg["detection_confidence_threshold"] == 0.85


def test_enabled_log_source_values_come_from_the_file(tmp_path: Path) -> None:
    """Written toggles win over any built-in defaults.

    evtx=false / cef=true deliberately invert the repo defaults, so a
    loader that ignored the file would fail these asserts.
    """
    text = "enabled_log_sources:\n  evtx: false\n  cef: true\n"
    cfg = load_config(str(_write_config(tmp_path, text)))
    sources = cfg["enabled_log_sources"]
    assert isinstance(sources, dict)
    assert sources.get("evtx") is False
    assert sources.get("cef") is True


def test_unknown_source_names_pass_through_unvalidated(tmp_path: Path) -> None:
    """Format-name validation is not the loader's job (mapper uses .get)."""
    text = "enabled_log_sources:\n  some_future_format: true\n"
    cfg = load_config(str(_write_config(tmp_path, text)))
    assert cfg["enabled_log_sources"].get("some_future_format") is True


def test_malformed_yaml_raises(tmp_path: Path) -> None:
    """Syntactically broken YAML raises instead of degrading to defaults.

    Accepts either a raw ``yaml.YAMLError`` family exception or a
    ``ValueError`` wrapping it; anything else (especially silent
    defaults) is a contract violation.
    """
    broken = "\tplatform_scope: windows\n  bad: :indent\n"
    with pytest.raises((yaml.YAMLError, ValueError)):
        load_config(str(_write_config(tmp_path, broken)))


def test_non_mapping_document_list(tmp_path: Path) -> None:
    """A top-level YAML list never comes back as a bogus 'config'."""
    _assert_rejected_or_normalized(
        str(_write_config(tmp_path, "- alpha\n- beta\n"))
    )


def test_non_mapping_document_scalar(tmp_path: Path) -> None:
    """A top-level YAML scalar is rejected or normalised, never passed through."""
    _assert_rejected_or_normalized(str(_write_config(tmp_path, "just-a-string\n")))


def test_default_argument_reads_repo_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """The ``path="config.yaml"`` default resolves to the repo-root file."""
    explicit = load_config(str(REPO_ROOT / "config.yaml"))
    monkeypatch.chdir(REPO_ROOT)
    defaulted = load_config()
    assert defaulted == explicit
    # Guard against a vacuous pass from two identical empty results.
    assert REQUIRED_KEYS.issubset(defaulted)
