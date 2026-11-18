"""Repo-root-relative default paths must not depend on the process CWD.

The Gap Analysis view used to read ``data/attack_mappings.csv`` relative to
the current working directory, which raised ``FileNotFoundError`` whenever the
dashboard was launched from outside the repository root -- the committed
``docs/screenshots/gap-analysis-all.png`` was that traceback.
"""
from __future__ import annotations

from pathlib import Path

from src.config_loader import DEFAULT_CONFIG_PATH, load_config
from src.parser.mappings_io import DEFAULT_MAPPINGS_PATH, load_mappings


def test_default_paths_live_at_repo_root() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assert DEFAULT_MAPPINGS_PATH == repo_root / "data" / "attack_mappings.csv"
    assert DEFAULT_CONFIG_PATH == repo_root / "config.yaml"
    assert DEFAULT_MAPPINGS_PATH.is_file()
    assert DEFAULT_CONFIG_PATH.is_file()


def test_loaders_work_from_an_unrelated_cwd(tmp_path, monkeypatch) -> None:
    """The dashboard must render regardless of where Streamlit was launched."""
    monkeypatch.chdir(tmp_path)

    rules = load_mappings(DEFAULT_MAPPINGS_PATH)
    assert rules, "mapping rules should load regardless of CWD"

    config = load_config(DEFAULT_CONFIG_PATH)
    assert config["platform_scope"]
    assert config["enabled_log_sources"]
