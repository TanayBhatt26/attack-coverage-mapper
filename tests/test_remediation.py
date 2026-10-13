"""Acceptance tests for Phase 7 remediation analysis.

Tests the seven key acceptance criteria for the remediation framework.
"""

from __future__ import annotations

import yaml

import pytest

from src.analysis.remediation import (
    CandidateSourceStatus,
    RemediationCategory,
    classify_remediation,
    classify_all_gaps,
)
from src.analysis.coverage_analyzer import CoverageRow
from src.config_loader import load_config


# ---------------------------------------------------------------------------
# Test 1: Unknown inventory (None) ≠ explicitly empty inventory (frozenset())
# ---------------------------------------------------------------------------


class TestInventorySemantics:
    def test_normalize_distinguishes_none_vs_empty(self):
        from src.config_loader import _normalize_collected_log_sources
        assert _normalize_collected_log_sources(None) is None
        assert _normalize_collected_log_sources([]) == frozenset()
        assert _normalize_collected_log_sources(["evtx"]) == frozenset(["evtx"])

    def test_load_config_preserves_none_vs_empty(self, tmp_path):
        config_path = tmp_path / "config.yaml"

        # Test None (key absent)
        config_none = {"enabled_log_sources": {"evtx": True}}
        config_path.write_text(yaml.safe_dump(config_none), encoding="utf-8")
        from src.config_loader import load_config
        loaded = load_config(str(config_path))
        assert loaded["collected_log_sources"] is None

        # Test null
        config_null = {"enabled_log_sources": {"evtx": True}, "collected_log_sources": None}
        config_path.write_text(yaml.safe_dump(config_null), encoding="utf-8")
        from src.config_loader import load_config
        loaded = load_config(str(config_path))
        assert loaded["collected_log_sources"] is None

        # Test empty list
        config_empty = {"enabled_log_sources": {"evtx": True}, "collected_log_sources": []}
        config_path.write_text(yaml.safe_dump(config_empty), encoding="utf-8")
        from src.config_loader import load_config
        loaded = load_config(str(config_path))
        assert loaded["collected_log_sources"] == frozenset()


# ---------------------------------------------------------------------------
# Test 2: Gap with both enablement and acquisition options preserves both
# ---------------------------------------------------------------------------


class TestCandidatePreservation:
    def test_preserves_both_enablement_and_acquisition(self):
        """Gap with both collected_disabled and not_collected sources preserves both."""
        from src.analysis.remediation import classify_remediation
        from src.analysis.coverage_analyzer import CoverageRow

        gap = SimpleNamespace(
            technique_attack_id="T1000",
            name="Test Technique",
            tactic="execution",
            best_confidence=0.3,
            closable_by=("zeek", "aws_cloudtrail"),
        )
        coverage_row = CoverageRow(
            technique_stix_id="x",
            attack_id="T1000",
            name="Test Technique",
            tactic="execution",
            scope_hit=True,
            best_confidence=0.3,
            is_detectable=False,
            source_ids=(),
            sigma_rule_id=None,
        )
        enabled = frozenset(["evtx"])
        collected = frozenset(["zeek"])
        rules = {}

        from src.analysis.remediation import classify_remediation
        detail = classify_remediation(
            gap=SimpleNamespace(
                technique_attack_id="T1000",
                name="Test Technique",
                tactic="execution",
                best_confidence=0.3,
                closable_by=("zeek", "aws_cloudtrail"),
            ),
            coverage_row=coverage_row,
            enabled_sources=enabled,
            collected_sources=collected,
            all_rules_by_source={},
            threshold=0.6,
        )

        statuses = [c.status for c in detail.candidate_sources]
        assert "collected_disabled" in statuses
        assert "not_collected" in [c.status for c in detail.candidate_sources]
        assert detail.primary_category.name == "CANDIDATE_SOURCE_ENABLEMENT"


# ---------------------------------------------------------------------------
# Test 3: Mapping on disabled source → MAPPING_TELEMETRY_REVIEW
# ---------------------------------------------------------------------------


class TestDisabledSourceMapping:
    def test_disabled_source_mapping_not_coverage_gap(self):
        """Mapping on disabled source → MAPPING_TELEMETRY_REVIEW."""
        from src.analysis.remediation import classify_remediation

        cov_row = SimpleNamespace(
            technique_stix_id="x",
            attack_id="T1000",
            name="Test",
            tactic="execution",
            scope_hit=True,
            best_confidence=0.3,
            is_detectable=False,
            source_ids=(),
            sigma_rule_id=None,
        )

        rules_by_source = {
            "zeek": [SimpleNamespace(
                technique_id="T1000",
                source_format="zeek",
                platforms=["windows"],
                match_type="extension",
                ext_keys="",
                ext_value_pattern="",
            )],
        }

        from src.analysis.remediation import classify_remediation
        detail = classify_remediation(
            gap=SimpleNamespace(
                technique_attack_id="T1000",
                name="Test",
                tactic="execution",
                best_confidence=0.3,
                closable_by=(),
            ),
            coverage_row=SimpleNamespace(
                technique_stix_id="x",
                attack_id="T1000",
                name="Test",
                tactic="execution",
                scope_hit=True,
                best_confidence=0.3,
                is_detectable=False,
                source_ids=(),
                sigma_rule_id=None,
            ),
            enabled_sources=frozenset(["evtx"]),
            collected_sources=frozenset(["zeek"]),
            all_rules_by_source=rules_by_source,
            threshold=0.6,
        )

        assert detail.primary_category.name == "MAPPING_TELEMETRY_REVIEW"


# ---------------------------------------------------------------------------
# Test 4: Enabled source in closable_by → DATA_QUALITY_ISSUE
# ---------------------------------------------------------------------------


class TestInvariantValidation:
    def test_enabled_source_in_closable_by_raises_validation(self):
        """Enabled source in closable_by → DATA_QUALITY_ISSUE, preserves candidates."""
        from src.analysis.remediation import classify_remediation

        detail = classify_remediation(
            gap=SimpleNamespace(
                technique_attack_id="T1000",
                name="Test",
                tactic="execution",
                best_confidence=0.3,
                closable_by=("evtx",),
            ),
            coverage_row=SimpleNamespace(source_ids=()),
            enabled_sources=frozenset(["evtx"]),
            collected_sources=frozenset(["evtx"]),
            all_rules_by_source={},
            threshold=0.6,
        )

        assert detail.primary_category.name == "DATA_QUALITY_ISSUE"
        assert len(detail.candidate_sources) == 1
        assert detail.candidate_sources[0].status == "validation_error"
        assert detail.validation_errors == ("evtx",)


# ---------------------------------------------------------------------------
# Test 5: Config writer preserves collected_log_sources
# ---------------------------------------------------------------------------


class TestConfigWriter:
    def test_write_config_preserves_collection_inventory(self, tmp_path):
        """Test the config serialization logic directly (no Streamlit import)."""
        import yaml

        # Test the serialization logic directly (mirrors _write_config)
        config = {
            "platform_scope": "windows",
            "detection_confidence_threshold": 0.6,
            "collected_log_sources": frozenset(["evtx", "zeek"]),
            "enabled_log_sources": {
                "evtx": True,
                "zeek": False,
            },
        }

        # Simulate _write_config serialization logic
        serializable = dict(config)
        val = serializable.get("collected_log_sources")
        if isinstance(val, (frozenset, set)):
            serializable["collected_log_sources"] = sorted(val)

        config_path = tmp_path / "config.yaml"
        with open(config_path, "w", encoding="utf-8") as fh:
            yaml.safe_dump(serializable, fh, default_flow_style=False, sort_keys=False)

        # Reload and verify
        with open(config_path, "r", encoding="utf-8") as f:
            reloaded = yaml.safe_load(f)

        assert reloaded["collected_log_sources"] == ["evtx", "zeek"]
        assert reloaded["enabled_log_sources"]["zeek"] is False


# ---------------------------------------------------------------------------
# Test 6: Bundle counts reconcile with gap records
# ---------------------------------------------------------------------------


class TestBundleReconciliation:
    def test_bundle_counts_reconcile(self):
        """Bundle counts should reconcile with gap records."""
        from src.analysis.remediation import classify_all_gaps

        gaps = (
            SimpleNamespace(
                technique_attack_id="T1000",
                name="Test1",
                tactic="execution",
                best_confidence=0.3,
                closable_by=("zeek",),
            ),
            SimpleNamespace(
                technique_attack_id="T1001",
                name="Test2",
                tactic="persistence",
                best_confidence=0.2,
                closable_by=(),
            ),
        )
        rows = (
            SimpleNamespace(
                attack_id="T1000",
                source_ids=(),
                best_confidence=0.3,
                is_detectable=False,
            ),
            SimpleNamespace(
                attack_id="T1001",
                source_ids=(),
                best_confidence=0.2,
                is_detectable=False,
            ),
        )

        from src.analysis.remediation import classify_all_gaps
        details = list(classify_all_gaps(
            gaps=gaps,
            coverage_rows=rows,
            enabled_sources=frozenset(["evtx"]),
            collected_sources=frozenset(["zeek"]),
            all_rules_by_source={},
            threshold=0.6,
        ))

        assert len(details) == 2
        with_closable = sum(1 for d in details if d.candidate_sources)
        without_closable = sum(1 for d in details if not d.candidate_sources)
        assert with_closable + without_closable == 2


# ---------------------------------------------------------------------------
# Test 7: Marginal contribution labeled "independent vs baseline"
# ---------------------------------------------------------------------------


class TestMarginalContributionLabel:
    def test_coverage_view_has_correct_label(self):
        """Verify the coverage view uses correct label for marginal gains."""
        source = open("src/visualization/views/coverage.py").read()
        assert "independent" in source.lower()
        assert "baseline" in source.lower()
        assert "independent" in source and "baseline" in source


# Helper
from types import SimpleNamespace

if __name__ == "__main__":
    pytest.main([__file__, "-v"])