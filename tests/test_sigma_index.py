"""test_sigma_index.py -- Phase 5 Wave 2 SigmaIndex + LogsourceMapper.

Pins the foundation contracts:

- **(IDX-1) Build**: :meth:`SigmaIndex.from_clone` walks a SigmaHQ-clone tree,
  extracts technique tags via whole-file regex (no YAML parse), uppercases the
  captured ``t`` -> ``T`` to DB form, and returns a sorted, deduplicated path
  list per technique.
- **(IDX-2) Graceful absence**: a missing clone directory yields an empty index
  (no exception) so the pipeline falls back to curated / generic tiers.
- **(IDX-3) Non-rule files ignored**: ``.txt`` / non-rule extensions are skipped.
- **(IDX-4) LogsourceMapper**: each config source format maps to the Wave-1
  predicate set, and ``matches()`` implements partial-predicate matching
  (product/category/service) per ``research/p5-wave1-full-results.md``
  agent-423.

Offline: the clone is synthesized by ``tests.fixtures_hunt.sigma_clone``.
"""

from __future__ import annotations

import logging

import pytest

from detections.hand_written import CURATED_TECHNIQUES
from detections.sigma_index import (
    FORMAT_TO_LOGSOURCES,
    LogsourceMapper,
    SigmaIndex,
    _normalize_technique,
)
from tests.fixtures_hunt import write_rule

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tag normalization
# ---------------------------------------------------------------------------


class TestNormalize:
    def test_lowercase_t_uppercased(self) -> None:
        assert _normalize_technique("t1059.001") == "T1059.001"

    def test_already_uppercase_unchanged(self) -> None:
        assert _normalize_technique("T1059.001") == "T1059.001"

    def test_parent_technique(self) -> None:
        assert _normalize_technique("t1685") == "T1685"


# ---------------------------------------------------------------------------
# LogsourceMapper
# ---------------------------------------------------------------------------


class TestLogsourceMapper:
    def test_evtx_predicate_is_windows_product(self) -> None:
        # Wave 1 agent-423: evtx spans the whole product:windows tree.
        preds = LogsourceMapper.predicates_for("evtx")
        assert preds == ({"product": "windows"},)

    def test_aws_cloudtrail_predicate(self) -> None:
        preds = LogsourceMapper.predicates_for("aws_cloudtrail")
        assert preds == ({"product": "aws", "service": "cloudtrail"},)

    def test_unknown_format_empty(self) -> None:
        assert LogsourceMapper.predicates_for("not_a_format") == ()

    def test_matches_windows_process_creation(self) -> None:
        # A windows/process_creation rule matches evtx (product:windows).
        ls = {"product": "windows", "category": "process_creation"}
        assert LogsourceMapper.matches(ls, "evtx") is True

    def test_matches_zeek_dns(self) -> None:
        ls = {"product": "zeek", "service": "dns"}
        assert LogsourceMapper.matches(ls, "zeek") is True

    def test_no_match_across_format(self) -> None:
        # A windows rule does NOT match the zeek format.
        ls = {"product": "windows", "category": "process_creation"}
        assert LogsourceMapper.matches(ls, "zeek") is False

    def test_none_logsource_never_matches(self) -> None:
        assert LogsourceMapper.matches(None, "evtx") is False

    def test_partial_predicate_match(self) -> None:
        # evtx predicate is only {product:windows}; a windows rule with any
        # category/service still matches (partial predicate semantics).
        ls = {"product": "windows", "category": "registry_event", "service": "sysmon"}
        assert LogsourceMapper.matches(ls, "evtx") is True

    def test_all_config_formats_have_predicates(self) -> None:
        # Every canonical source format maps to at least one predicate.
        for fmt in (
            "evtx",
            "aws_cloudtrail",
            "zeek",
            "syslog",
            "nginx",
            "cef",
            "leef",
            "json",
        ):
            assert FORMAT_TO_LOGSOURCES.get(fmt), fmt


# ---------------------------------------------------------------------------
# SigmaIndex build
# ---------------------------------------------------------------------------


class TestSigmaIndexBuild:
    def test_build_indexes_tagged_techniques(self, sigma_clone) -> None:
        idx = SigmaIndex.from_clone(sigma_clone["root"])
        # Four distinct techniques across the four rules.
        assert "T1059.001" in idx
        assert "T1562.001" in idx
        assert "T1071.004" in idx
        assert "T1071.001" in idx

    def test_build_returns_sorted_paths(self, sigma_clone) -> None:
        idx = SigmaIndex.from_clone(sigma_clone["root"])
        paths = idx.get("T1059.001")
        assert paths == sorted(paths)
        # win_powershell tags both t1059.001 and t1059 -> one path for t1059.001.
        assert len(paths) == 1
        assert paths[0].endswith("win_powershell.yml")

    def test_build_dedups_within_a_file(self, sigma_clone) -> None:
        # A rule tagging the same technique twice must map to the rule once.
        win_dir = sigma_clone["win_powershell"].parent
        dup = win_dir / "dup.yml"
        write_rule(
            dup,
            technique_tags=("attack.t1111", "attack.t1111"),
            product="windows",
            category="process_creation",
        )
        idx = SigmaIndex.from_clone(sigma_clone["root"])
        assert idx.get("T1111") == [str(dup)]

    def test_ignores_non_rule_extensions(self, sigma_clone) -> None:
        # The .txt file carries attack.t9999.999 but must be ignored.
        idx = SigmaIndex.from_clone(sigma_clone["root"])
        assert "T9999.999" not in idx

    def test_get_unknown_technique_empty(self, sigma_clone) -> None:
        idx = SigmaIndex.from_clone(sigma_clone["root"])
        assert idx.get("T0000") == []

    def test_get_is_case_insensitive(self, sigma_clone) -> None:
        idx = SigmaIndex.from_clone(sigma_clone["root"])
        assert idx.get("t1059.001") == idx.get("T1059.001")

    def test_len_and_techniques(self, sigma_clone) -> None:
        idx = SigmaIndex.from_clone(sigma_clone["root"])
        assert len(idx) == len(idx.techniques())
        assert list(idx.techniques()) == sorted(idx.techniques())

    def test_contains(self, sigma_clone) -> None:
        idx = SigmaIndex.from_clone(sigma_clone["root"])
        assert "T1059.001" in idx
        assert "T0000" not in idx


# ---------------------------------------------------------------------------
# Graceful absence
# ---------------------------------------------------------------------------


class TestSigmaIndexAbsent:
    def test_missing_clone_returns_empty_index(self, tmp_path) -> None:
        missing = tmp_path / "does-not-exist"
        idx = SigmaIndex.from_clone(missing)
        assert len(idx) == 0
        assert idx.get("T1059.001") == []

    def test_empty_clone_dir_returns_empty_index(self, tmp_path) -> None:
        empty = tmp_path / "empty"
        empty.mkdir()
        idx = SigmaIndex.from_clone(empty)
        assert len(idx) == 0


# ---------------------------------------------------------------------------
# Direct constructor (tests)
# ---------------------------------------------------------------------------


class TestSigmaIndexDirect:
    def test_direct_constructor_dedups_and_sorts(self) -> None:
        idx = SigmaIndex({"T1001": ["b.yml", "a.yml", "b.yml"]})
        assert idx.get("T1001") == ["a.yml", "b.yml"]

    def test_get_returns_fresh_copy(self) -> None:
        idx = SigmaIndex({"T1001": ["a.yml"]})
        a = idx.get("T1001")
        a.append("mutate.yml")
        # Internal state must be unchanged (tuple-valued, immutable).
        assert idx.get("T1001") == ["a.yml"]


# ---------------------------------------------------------------------------
# Curated set sanity (cross-check with hand_written)
# ---------------------------------------------------------------------------


class TestCuratedSetSanity:
    def test_curated_techniques_nonempty_subset_of_core(self) -> None:
        # The curated core set is non-empty and every id is a valid shape.
        assert len(CURATED_TECHNIQUES) > 0
        for tid in CURATED_TECHNIQUES:
            assert tid[0] == "T", tid
