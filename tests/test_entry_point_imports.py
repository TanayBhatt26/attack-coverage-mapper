"""Entry-point import bootstrap guards.

``src/visualization/app.py`` mixes two import styles: ``database.*`` (which
lives under ``src/``) and ``src.*`` (which needs the repository root). Streamlit
Community Cloud executes the entry point with *neither* directory on
``sys.path`` and no ``PYTHONPATH``, so the bootstrap must add both.

This has regressed twice: ``parents[1]`` made ``src.*`` unresolvable, then
``parents[2]`` made ``database.*`` unresolvable (the Streamlit Cloud
``ModuleNotFoundError``). The tests below reproduce both conditions in a clean
interpreter rather than trusting the dev machine's ``PYTHONPATH``.
"""
from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
APP_ENTRY = REPO_ROOT / "src" / "visualization" / "app.py"

MODULES = ("database.session", "src.config_loader")


def _import_with_only(roots: list[Path]) -> dict[str, str | None]:
    """Import :data:`MODULES` in a clean interpreter holding only ``roots``.

    Returns a mapping of module name to the ``ModuleNotFoundError`` text, or
    ``None`` when the import succeeded. ``-I`` isolates the child interpreter
    from ``PYTHONPATH``/the current directory, so the result reflects only the
    roots handed to it -- the same situation Streamlit Cloud creates.
    """
    code = (
        "import sys\n"
        f"sys.path[:0] = {[str(root) for root in roots]!r}\n"
        "result = {}\n"
        f"for name in {list(MODULES)!r}:\n"
        "    try:\n"
        "        __import__(name)\n"
        "        result[name] = None\n"
        "    except ModuleNotFoundError as exc:\n"
        "        result[name] = str(exc)\n"
        "print(repr(result))\n"
    )
    proc = subprocess.run(
        [sys.executable, "-I", "-c", code],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    assert proc.returncode == 0, proc.stderr
    return ast.literal_eval(proc.stdout.strip().splitlines()[-1])


def test_both_roots_together_resolve_everything() -> None:
    """The fixed bootstrap: repo root plus src/ resolves both import styles."""
    failures = _import_with_only([REPO_ROOT, REPO_ROOT / "src"])
    assert failures == {name: None for name in MODULES}, failures


@pytest.mark.parametrize(
    "roots, broken",
    [
        ([REPO_ROOT], "database.session"),
        ([REPO_ROOT / "src"], "src.config_loader"),
    ],
)
def test_a_single_root_is_not_enough(roots: list[Path], broken: str) -> None:
    """Documents why both roots are required.

    Each single-root configuration reproduces a failure that has actually
    shipped, so the pair of tests pins the contract from both sides.
    """
    failures = _import_with_only(roots)
    assert failures[broken] is not None, failures
    other = next(name for name in MODULES if name != broken)
    assert failures[other] is None, failures


def test_entry_point_bootstrap_is_wired_to_both_roots() -> None:
    """The entry point must itself add both roots, not rely on the caller."""
    source = APP_ENTRY.read_text(encoding="utf-8")
    assert "parents[2]" in source, (
        "app.py must derive the repository root from __file__"
    )
    assert '/ "src"' in source or "/ 'src'" in source, (
        "app.py must also put the src/ directory on sys.path"
    )
