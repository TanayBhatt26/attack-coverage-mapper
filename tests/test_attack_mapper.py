"""Unit tests for the parser.attack_mapper tiered matching engine.

Verifies the shared Phase 2 contract: tier precedence (extension >
action > format-level heuristic), confidence math (base * 1.0 / 0.85
/ 0.40, capped at 0.95), per-technique dedupe keeping the highest
score, tactic union, datasource_type mapping, and disabled-log-source
behaviour.

Interpretive note: tier 3 is specified as the home of
``match_type="heuristic"`` rules ("passes its normal ext/action
checks, whichever it declares"). These tests treat heuristic rules as
bypassing tiers 1-2 so that tier 3 is reachable whenever no stronger
rule matched anywhere; otherwise tier 3 could never fire, since its
re-checked conditions are identical to the tier 1/2 gates.
"""

import re

import pytest

from parser.attack_mapper import map_events, map_log_event, score_for_tier
from parser.log_event_bridge import LogEvent
from parser.mappings_io import MappingRule

pytestmark = pytest.mark.unit

_RULE_SEQ = iter(range(1000))


def make_rule(**overrides) -> MappingRule:
    """Build a MappingRule with contract-valid defaults; override any field."""
    defaults = {
        "mapping_id": f"M{900 + next(_RULE_SEQ)}",
        "source_format": "evtx",
        "event_action_re": None,
        "ext_keys": (),
        "ext_value_re": None,
        "match_type": "exact",
        "is_core": False,
        "technique_id": "T1059",
        "tactic": "execution",
        "base_confidence": 0.8,
        "visibility_hint": 2,
        "evidence_ref": "test://rule",
        "sigma_rule_id": None,
        "notes": "",
    }
    defaults.update(overrides)
    return MappingRule(**defaults)


def make_event(**overrides) -> LogEvent:
    """Build a LogEvent with minimal defaults; override any field."""
    defaults = {
        "source_format": "evtx",
        "event_action": None,
        "extensions": {},
    }
    defaults.update(overrides)
    return LogEvent(**defaults)


def make_config(**enabled_overrides) -> dict:
    """Build a config dict with every known format enabled by default."""
    enabled = {
        "evtx": True,
        "syslog": True,
        "cef": True,
        "leef": True,
        "json": True,
        "aws_cloudtrail": True,
        "nginx": True,
        "zeek": True,
    }
    enabled.update(enabled_overrides)
    return {
        "platform_scope": "windows",
        "detection_confidence_threshold": 0.6,
        "enabled_log_sources": enabled,
    }


class TestScoreForTier:
    """Pure-helper confidence math per tier."""

    def test_tier1_is_full_base(self):
        """Tier 1 applies the base confidence unchanged."""
        assert score_for_tier(0.8, 1) == pytest.approx(0.8)

    def test_tier2_is_base_times_085(self):
        """Tier 2 discounts the base confidence by 15 percent."""
        assert score_for_tier(0.8, 2) == pytest.approx(0.8 * 0.85)

    def test_tier3_is_base_times_040(self):
        """Tier 3 discounts the base confidence to 40 percent."""
        assert score_for_tier(0.5, 3) == pytest.approx(0.5 * 0.40)

    def test_scores_decrease_across_tiers(self):
        """Stronger evidence tiers always outrank weaker ones pre-cap."""
        base = 0.8
        assert (
            score_for_tier(base, 1)
            > score_for_tier(base, 2)
            > score_for_tier(base, 3)
        )


class TestTier1ExtensionMatch:
    """Tier 1: extension-key evidence, confidence = base * 1.0."""

    def test_ext_key_present_no_value_regex(self):
        """Key existence alone satisfies an exists-style rule at full base."""
        rule = make_rule(
            match_type="exists",
            ext_keys=("targetusername",),
            technique_id="T1136.001",
            tactic="persistence",
            base_confidence=0.85,
        )
        event = make_event(extensions={"TargetUserName": "bob"})
        result = map_log_event(event, [rule], make_config())
        assert result.attack_technique_ids == ["T1136.001"]
        assert result.detection_confidence == pytest.approx(0.85)

    def test_ext_key_lookup_is_case_insensitive(self):
        """Rule ext_keys are lowercase; event extension keys match ignoring case."""
        rule = make_rule(
            match_type="regex",
            ext_keys=("newprocessname",),
            ext_value_re=re.compile(r"(?i)\\cmd\.exe"),
            technique_id="T1059.003",
            base_confidence=0.7,
        )
        event = make_event(
            event_action="process_created",
            extensions={"NewProcessName": "C:\\Windows\\System32\\cmd.exe"},
        )
        result = map_log_event(event, [rule], make_config())
        assert result.attack_technique_ids == ["T1059.003"]
        assert result.detection_confidence == pytest.approx(0.7)

    def test_ext_value_matched_against_str_of_int(self):
        """Non-string extension values are coerced with str() before regex."""
        rule = make_rule(
            match_type="regex",
            ext_keys=("logontype",),
            ext_value_re=re.compile(r"^3$"),
            technique_id="T1021",
            tactic="lateral-movement",
            base_confidence=0.5,
        )
        event = make_event(
            event_action="logon_success",
            extensions={"LogonType": 3},
        )
        result = map_log_event(event, [rule], make_config())
        assert result.attack_technique_ids == ["T1021"]

    def test_ext_value_regex_mismatch_yields_no_match(self):
        """A failing ext_value_re leaves the non-heuristic rule unmatched."""
        rule = make_rule(
            match_type="regex",
            ext_keys=("logontype",),
            ext_value_re=re.compile(r"^3$"),
            technique_id="T1021",
            base_confidence=0.5,
        )
        event = make_event(
            event_action="logon_success",
            extensions={"LogonType": 10},
        )
        result = map_log_event(event, [rule], make_config())
        assert result.attack_technique_ids == []
        assert result.detection_confidence == 0.0

    def test_ext_key_absent_yields_no_match(self):
        """No declared key present means no tier 1 hit."""
        rule = make_rule(
            match_type="exists",
            ext_keys=("targetusername",),
            technique_id="T1136.001",
            base_confidence=0.85,
        )
        event = make_event(event_action="user_account_created")
        result = map_log_event(event, [rule], make_config())
        assert result.attack_technique_ids == []

    def test_any_declared_key_present_satisfies_tier1(self):
        """A hit on any single declared ext_keys entry satisfies tier 1."""
        rule = make_rule(
            match_type="regex",
            ext_keys=("logontype", "ipaddress"),
            ext_value_re=re.compile(r"^3$"),
            technique_id="T1021",
            base_confidence=0.35,
        )
        # Only the second declared key is present; its value matches ^3$.
        event = make_event(
            event_action="logon_success",
            extensions={"IpAddress": "3"},
        )
        result = map_log_event(event, [rule], make_config())
        assert result.attack_technique_ids == ["T1021"]
        assert result.detection_confidence == pytest.approx(0.35)

    def test_rules_from_other_formats_are_ignored(self):
        """Candidates are restricted to rules whose source_format matches."""
        rule = make_rule(
            source_format="syslog",
            event_action_re=re.compile(r"^logon_failure$"),
            technique_id="T1110.001",
            base_confidence=0.6,
        )
        event = make_event(
            source_format="evtx",
            event_action="logon_failure",
        )
        result = map_log_event(event, [rule], make_config())
        assert result.attack_technique_ids == []


class TestTier2ActionMatch:
    """Tier 2: action-only rules, confidence = base * 0.85."""

    def test_action_fullmatch_scores_085_factor(self):
        """A matching action pattern earns base discounted to 85 percent."""
        rule = make_rule(
            match_type="regex",
            event_action_re=re.compile(r"^logon_failure$"),
            technique_id="T1110.001",
            tactic="credential-access",
            base_confidence=0.6,
        )
        event = make_event(event_action="logon_failure")
        result = map_log_event(event, [rule], make_config())
        assert result.attack_technique_ids == ["T1110.001"]
        assert result.detection_confidence == pytest.approx(0.6 * 0.85)

    def test_partial_action_string_fails_fullmatch(self):
        """event_action_re uses fullmatch, so suffixes break the match."""
        rule = make_rule(
            match_type="regex",
            event_action_re=re.compile(r"^logon_failure$"),
            technique_id="T1110.001",
            base_confidence=0.6,
        )
        event = make_event(event_action="logon_failure_locked_account")
        result = map_log_event(event, [rule], make_config())
        assert result.attack_technique_ids == []

    def test_none_event_action_never_matches(self):
        """An event without an action cannot satisfy an action rule."""
        rule = make_rule(
            match_type="exact",
            event_action_re=re.compile(r"^logon_failure$"),
            technique_id="T1110.001",
            base_confidence=0.6,
        )
        event = make_event(event_action=None)
        result = map_log_event(event, [rule], make_config())
        assert result.attack_technique_ids == []

    def test_rule_with_ext_keys_is_not_eligible_for_tier2(self):
        """Tier 2 requires empty ext_keys; an ext rule matching on action alone is inert."""
        rule = make_rule(
            match_type="regex",
            event_action_re=re.compile(r"^process_created$"),
            ext_keys=("commandline",),
            ext_value_re=re.compile(r"(?i)schtasks"),
            technique_id="T1053.005",
            base_confidence=0.75,
        )
        event = make_event(event_action="process_created", extensions={})
        result = map_log_event(event, [rule], make_config())
        assert result.attack_technique_ids == []


class TestTier3HeuristicFallback:
    """Tier 3: heuristic-only weak tier, confidence = base * 0.40."""

    def test_lone_heuristic_action_rule_scores_040_factor(self):
        """A heuristic action-only rule matches only via tier 3, at 40 percent."""
        rule = make_rule(
            source_format="aws_cloudtrail",
            match_type="heuristic",
            event_action_re=re.compile(r"^GetCallerIdentity$"),
            technique_id="T1580",
            tactic="discovery",
            base_confidence=0.45,
        )
        event = make_event(
            source_format="aws_cloudtrail",
            event_action="GetCallerIdentity",
            extensions={"event_source": "sts.amazonaws.com"},
        )
        result = map_log_event(event, [rule], make_config())
        assert result.attack_technique_ids == ["T1580"]
        assert result.detection_confidence == pytest.approx(0.45 * 0.40)
        assert result.attack_tactics == ["discovery"]

    def test_heuristic_with_unmet_check_never_matches(self):
        """A heuristic rule whose declared check fails contributes nothing."""
        rule = make_rule(
            match_type="heuristic",
            ext_keys=("parentimage",),
            technique_id="T1036",
            base_confidence=0.4,
        )
        event = make_event(event_action="process_created", extensions={})
        result = map_log_event(event, [rule], make_config())
        assert result.attack_technique_ids == []
        assert result.detection_confidence == 0.0

    def test_heuristic_skipped_when_any_stronger_match_exists(self):
        """Tier 3 runs only when zero tier 1/2 matches occurred across all candidates."""
        strong = make_rule(
            match_type="regex",
            event_action_re=re.compile(r"^process_created$"),
            ext_keys=("newprocessname",),
            ext_value_re=re.compile(r"(?i)\\cmd\.exe"),
            technique_id="T1059.003",
            base_confidence=0.7,
        )
        weak = make_rule(
            match_type="heuristic",
            event_action_re=re.compile(r"^process_created$"),
            technique_id="T1046",
            base_confidence=0.45,
        )
        event = make_event(
            event_action="process_created",
            extensions={"NewProcessName": "C:\\Windows\\System32\\cmd.exe"},
        )
        result = map_log_event(event, [strong, weak], make_config())
        assert result.attack_technique_ids == ["T1059.003"]
        assert result.detection_confidence == pytest.approx(0.7)


class TestPrecedenceAndDedupe:
    """Cross-tier precedence and per-technique dedupe semantics."""

    def test_same_technique_keeps_highest_tier_score(self):
        """Dedupe per technique_id retains the tier 1 score over tier 2."""
        via_ext = make_rule(
            match_type="exists",
            event_action_re=re.compile(r"^user_account_created$"),
            ext_keys=("targetusername",),
            technique_id="T1136.001",
            base_confidence=0.9,
        )
        via_action = make_rule(
            match_type="exact",
            event_action_re=re.compile(r"^user_account_created$"),
            technique_id="T1136.001",
            base_confidence=0.9,
        )
        event = make_event(
            event_action="user_account_created",
            extensions={"TargetUserName": "bob"},
        )
        for rules in ([via_ext, via_action], [via_action, via_ext]):
            result = map_log_event(event, rules, make_config())
            assert result.attack_technique_ids.count("T1136.001") == 1
            assert result.detection_confidence == pytest.approx(0.9)

    def test_distinct_techniques_are_all_preserved(self):
        """Union semantics: different technique_ids from different tiers coexist."""
        tier1_rule = make_rule(
            match_type="exists",
            ext_keys=("targetusername",),
            technique_id="T1136.001",
            tactic="persistence",
            base_confidence=0.85,
        )
        tier2_rule = make_rule(
            match_type="regex",
            event_action_re=re.compile(r"^logon_failure$"),
            technique_id="T1110.001",
            tactic="credential-access",
            base_confidence=0.6,
        )
        event = make_event(
            event_action="logon_failure",
            extensions={"TargetUserName": "bob"},
        )
        result = map_log_event(event, [tier1_rule, tier2_rule], make_config())
        assert sorted(result.attack_technique_ids) == [
            "T1110.001",
            "T1136.001",
        ]

    def test_attack_tactics_is_sorted_union_of_kept_rules(self):
        """attack_tactics collects kept-rule tactics, sorted alphabetically."""
        rule_a = make_rule(
            match_type="exists",
            ext_keys=("targetusername",),
            technique_id="T1136.001",
            tactic="persistence",
            base_confidence=0.85,
        )
        rule_b = make_rule(
            match_type="regex",
            event_action_re=re.compile(r"^logon_failure$"),
            technique_id="T1110.001",
            tactic="credential-access",
            base_confidence=0.6,
        )
        event = make_event(
            event_action="logon_failure",
            extensions={"TargetUserName": "bob"},
        )
        result = map_log_event(event, [rule_a, rule_b], make_config())
        assert result.attack_tactics == ["credential-access", "persistence"]


class TestConfidenceCap:
    """The 0.95 ceiling applied to any computed score."""

    def test_perfect_tier1_score_is_capped(self):
        """base 1.0 at tier 1 clamps to 0.95, not 1.0."""
        rule = make_rule(
            match_type="exists",
            ext_keys=("targetusername",),
            technique_id="T1136.001",
            base_confidence=1.0,
        )
        event = make_event(extensions={"TargetUserName": "bob"})
        result = map_log_event(event, [rule], make_config())
        assert result.detection_confidence == pytest.approx(0.95)

    def test_cap_does_not_touch_midrange_scores(self):
        """Scores below the ceiling pass through unchanged."""
        rule = make_rule(
            match_type="exists",
            ext_keys=("targetusername",),
            technique_id="T1136.001",
            base_confidence=0.9,
        )
        event = make_event(extensions={"TargetUserName": "bob"})
        result = map_log_event(event, [rule], make_config())
        assert result.detection_confidence == pytest.approx(0.9)

    def test_tier2_and_tier3_math_exact_values(self):
        """Spot-check representative discount products for tiers 2 and 3."""
        assert 0.7 * 0.85 == pytest.approx(0.595)
        assert 0.45 * 0.40 == pytest.approx(0.18)


class TestDatasourceTypeMapping:
    """Static source_format to datasource_type translation."""

    @pytest.mark.parametrize(
        ("source_format", "expected_datasource"),
        [
            ("evtx", "windows:eventlog"),
            ("syslog", "linux:syslog"),
            ("cef", "network:device"),
            ("leef", "network:device"),
            ("json", "generic:json"),
            ("aws_cloudtrail", "cloud:cloudtrail"),
            ("nginx", "web:access"),
            ("zeek", "network:zeek"),
        ],
    )
    def test_known_formats(self, source_format, expected_datasource):
        """Every supported format maps to its fixed datasource label."""
        event = make_event(source_format=source_format)
        result = map_log_event(event, [], make_config())
        assert result.datasource_type == expected_datasource

    def test_unknown_format_gets_prefixed_label(self):
        """Unrecognized formats fall back to unknown:<format>."""
        event = make_event(source_format="kafka")
        result = map_log_event(event, [], make_config())
        assert result.datasource_type == "unknown:kafka"
        assert result.attack_technique_ids == []

    def test_empty_rules_still_sets_datasource(self):
        """datasource_type is derived even when nothing can match."""
        event = make_event(source_format="zeek")
        result = map_log_event(event, [], make_config())
        assert result.datasource_type == "network:zeek"
        assert result.attack_technique_ids == []
        assert result.attack_tactics == []
        assert result.detection_confidence == 0.0


class TestDisabledLogSource:
    """enabled_log_sources toggling suppresses matching but not labelling."""

    def test_disabled_source_clears_annotations_keeps_datasource(self):
        """A disabled format skips matching entirely; datasource survives."""
        rule = make_rule(
            match_type="regex",
            event_action_re=re.compile(r"^logon_failure$"),
            technique_id="T1110.001",
            tactic="credential-access",
            base_confidence=0.6,
        )
        event = make_event(source_format="evtx", event_action="logon_failure")
        config = make_config(evtx=False)
        result = map_log_event(event, [rule], config)
        assert result.attack_technique_ids == []
        assert result.attack_tactics == []
        assert result.detection_confidence == 0.0
        assert result.datasource_type == "windows:eventlog"

    def test_missing_format_entry_defaults_to_enabled(self):
        """Formats absent from enabled_log_sources are not treated as disabled."""
        rule = make_rule(
            match_type="regex",
            event_action_re=re.compile(r"^logon_failure$"),
            technique_id="T1110.001",
            base_confidence=0.6,
        )
        event = make_event(source_format="evtx", event_action="logon_failure")
        config = make_config()
        del config["enabled_log_sources"]["evtx"]
        result = map_log_event(event, [rule], config)
        assert result.attack_technique_ids == ["T1110.001"]
        assert result.detection_confidence == pytest.approx(0.6 * 0.85)


class TestMapEventsBatch:
    """map_events batch wrapper behaviour."""

    def test_batch_maps_in_order_and_mutates_inputs(self):
        """Results keep input order and carry the enriched event objects."""
        hit = make_rule(
            match_type="regex",
            event_action_re=re.compile(r"^logon_failure$"),
            technique_id="T1110.001",
            base_confidence=0.6,
        )
        events = [
            make_event(source_format="evtx", event_action="logon_failure"),
            make_event(source_format="evtx", event_action="audit_log_cleared"),
            make_event(
                source_format="evtx",
                event_action="process_created",
                extensions={"NewProcessName": "C:\\Windows\\System32\\cmd.exe"},
            ),
        ]
        results = map_events(events, [hit], make_config())
        assert isinstance(results, list)
        assert len(results) == 3
        assert results[0] is events[0]
        assert results[0].attack_technique_ids == ["T1110.001"]
        assert results[1].attack_technique_ids == []
        # audit_log_cleared does not fullmatch ^logon_failure$ nor carry ext keys.
        assert results[2].attack_technique_ids == []

    def test_single_event_api_returns_same_object(self):
        """map_log_event mutates and returns the very event it was given."""
        rule = make_rule(
            match_type="exists",
            ext_keys=("targetusername",),
            technique_id="T1136.001",
            base_confidence=0.85,
        )
        event = make_event(extensions={"TargetUserName": "bob"})
        result = map_log_event(event, [rule], make_config())
        assert result is event
        assert event.attack_technique_ids == ["T1136.001"]
