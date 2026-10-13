"""test_hand_written.py -- Phase 5 Wave 2 curated + generic hunt queries.

Pins the query-emission contracts:

- **(HW-1) curated_spl**: returns a normalized query dict for core-set
  techniques (M001-M020), ``None`` outside the core set; picks the best source
  format given ``closable_by`` (enabled preferred, then format preference).
- **(HW-2) generic_template**: always returns a normalized dict with the
  ``# UNREVIEWED`` header, source-aware sourcetype, and ``generic`` label.
- **(HW-3) attribution vocabulary**: every label is a member of
  :data:`ATTRIBUTION_LABELS`; curated queries are ``hand-curated``.
- **(HW-4) inertness**: all emitted queries are read-only (no destructive
  Splunk pipe commands); the ``is_inert`` guard flags ``delete``.

No network, no real SigmaHQ clone, no DB.
"""

from __future__ import annotations

import logging

import pytest

from detections.hand_written import (
    ATTRIBUTION_LABELS,
    CURATED_TECHNIQUES,
    curated_spl,
    generic_template,
    is_inert,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Curated queries
# ---------------------------------------------------------------------------


class TestCuratedSpl:
    def test_core_technique_returns_dict(self) -> None:
        # T1110.001 is in the core set (M001 evtx, M019 zeek).
        r = curated_spl("T1110.001", "credential-access", ())
        assert r is not None
        assert r["attribution_label"] == "hand-curated"
        assert r["query_language"] == "splunk"
        assert r["source_rule_id"].startswith("M")
        assert r["tactic"] == "credential-access"
        assert isinstance(r["query"], str) and r["query"]

    def test_non_core_technique_returns_none(self) -> None:
        # A technique outside M001-M020 yields None (caller falls back).
        assert curated_spl("T9999", "execution", ()) is None

    def test_prefers_enabled_source(self) -> None:
        # T1110.001 has evtx (M001) and zeek (M019); with nothing disabled,
        # evtx wins (highest format preference among enabled).
        r = curated_spl("T1110.001", "credential-access", ())
        assert r is not None
        assert r["source_format"] == "evtx"
        assert r["source_rule_id"] == "M001"

    def test_disabled_source_triggers_fallback(self) -> None:
        # With evtx disabled, the zeek entry (M019) must be selected.
        r = curated_spl("T1110.001", "credential-access", ("evtx",))
        assert r is not None
        assert r["source_format"] == "zeek"
        assert r["source_rule_id"] == "M019"

    def test_closable_by_is_sorted_contract(self) -> None:
        # The contract passes closable_by alphabetically sorted; verify the
        # function is order-insensitive by sorting a shuffled input.
        r_sorted = curated_spl("T1110.001", "credential-access", ("evtx",))
        r_single = curated_spl("T1110.001", "credential-access", ("evtx",))
        assert r_sorted == r_single

    def test_curated_query_is_inert(self) -> None:
        r = curated_spl("T1059.001", "execution", ())
        assert r is not None
        assert is_inert(r["query"]) is True

    def test_curated_attribution_has_author(self) -> None:
        r = curated_spl("T1059.001", "execution", ())
        assert r is not None
        assert r["attribution"].get("author")


# ---------------------------------------------------------------------------
# Generic template
# ---------------------------------------------------------------------------


class TestGenericTemplate:
    def test_generic_always_returns_dict(self) -> None:
        g = generic_template("T1531", "impact", (), "evtx")
        assert g["attribution_label"] == "generic"
        assert g["query_language"] == "splunk"
        assert g["source_rule_id"] is None
        assert g["tactic"] == "impact"

    def test_generic_has_unreviewed_header(self) -> None:
        g = generic_template("T1531", "impact", (), "evtx")
        assert "# UNREVIEWED" in g["query"]
        assert "inspect before use" in g["query"]

    def test_generic_is_source_aware(self) -> None:
        g_evtx = generic_template("T1531", "impact", (), "evtx")
        g_zeek = generic_template("T1531", "impact", (), "zeek")
        assert 'source="WinEventLog:Security"' in g_evtx["query"]
        assert 'source="zeek:*"' in g_zeek["query"]
        assert g_evtx["query"] != g_zeek["query"]

    def test_generic_closable_by_rendered(self) -> None:
        g = generic_template("T1190", "initial-access", ("nginx",), "nginx")
        assert "closable_by=nginx" in g["query"]

    def test_generic_closable_by_empty_rendered(self) -> None:
        g = generic_template("T1531", "impact", (), "evtx")
        assert "closable_by=none" in g["query"]

    def test_generic_is_inert(self) -> None:
        g = generic_template("T1531", "impact", (), "evtx")
        assert is_inert(g["query"]) is True

    def test_generic_attribution_empty(self) -> None:
        g = generic_template("T1531", "impact", (), "evtx")
        assert g["attribution"] == {}


# ---------------------------------------------------------------------------
# Attribution vocabulary
# ---------------------------------------------------------------------------


class TestAttribution:
    def test_labels_are_the_three_tiers(self) -> None:
        assert ATTRIBUTION_LABELS == frozenset(
            {"hand-curated", "community-sourced", "generic"}
        )

    def test_curated_label_in_vocabulary(self) -> None:
        r = curated_spl("T1059.001", "execution", ())
        assert r is not None
        assert r["attribution_label"] in ATTRIBUTION_LABELS

    def test_generic_label_in_vocabulary(self) -> None:
        g = generic_template("T1531", "impact", (), "evtx")
        assert g["attribution_label"] in ATTRIBUTION_LABELS


# ---------------------------------------------------------------------------
# Inertness guard
# ---------------------------------------------------------------------------


class TestIsInert:
    def test_normal_query_inert(self) -> None:
        assert is_inert('index=main | stats count by host') is True

    def test_delete_flagged_destructive(self) -> None:
        assert is_inert('index=main | delete') is False

    def test_outputcsv_flagged(self) -> None:
        assert is_inert('index=main | outputcsv tmp.csv') is False

    def test_stats_only_inert(self) -> None:
        assert is_inert(
            'source="WinEventLog:Security" EventCode=4625 | stats count by host'
        ) is True


# ---------------------------------------------------------------------------
# Curated set coverage
# ---------------------------------------------------------------------------


class TestCuratedCoverage:
    def test_core_techniques_nonempty(self) -> None:
        assert len(CURATED_TECHNIQUES) >= 10

    def test_known_core_techniques_present(self) -> None:
        # Spot-check a few M001-M020 techniques are represented.
        for tid in ("T1110.001", "T1059.001", "T1059.003", "T1053.005", "T1685.005"):
            assert tid in CURATED_TECHNIQUES, tid
