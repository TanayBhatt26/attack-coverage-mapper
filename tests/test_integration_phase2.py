"""Phase 2 integration tests (FR-8): real bundled sample logs end-to-end.

Exercises the Phase 2 chain over the real artifacts shipped in ``data/``:

    sample log file -> parser.siem_parsers.parse_log_content()
                    -> parser.mappings_io.load_mappings()
                    -> parser.attack_mapper.map_events()
                    -> enriched LogEvent annotations

Every expectation below is derived from the actual bytes of the bundled
samples (``data/sample_logs/*``) and the curated mapping set
(``data/attack_mappings.csv``, 83 rows, M001-M020 core), using the tier
scoring contract: extension x1.0 (a row's own action pattern is not
consulted on the extension tier), event-action x0.85, format-level
heuristic x0.40 (only when nothing stronger matched), capped at 0.95.

No network access; no writes outside ``tmp_path``.
"""

import dataclasses
import logging
import re
from pathlib import Path

import pytest

from config_loader import load_config
from parser.attack_mapper import map_events, map_log_event, score_for_tier
from parser.log_event_bridge import LogEvent
from parser.mappings_io import MappingRule, load_mappings
from parser.siem_parsers import parse_log_content

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.integration]

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_LOGS = REPO_ROOT / "data" / "sample_logs"
MAPPINGS_CSV = REPO_ROOT / "data" / "attack_mappings.csv"
REPO_CONFIG = REPO_ROOT / "config.yaml"

KNOWN_FORMATS = (
    "evtx",
    "syslog",
    "cef",
    "leef",
    "json",
    "aws_cloudtrail",
    "nginx",
    "zeek",
)


def read_sample(name: str) -> str:
    """Return the text content of a bundled sample log."""
    return (SAMPLE_LOGS / name).read_text(encoding="utf-8")


def make_config(threshold: float = 0.0, enabled: dict | None = None) -> dict:
    """Build a fresh engine config dict; threshold 0.0 keeps every match."""
    return {
        "platform_scope": "all",
        "detection_confidence_threshold": threshold,
        "enabled_log_sources": (
            dict(enabled) if enabled is not None else {fmt: True for fmt in KNOWN_FORMATS}
        ),
    }


def parse_and_map(content: str, fmt: str, rules: list, config: dict) -> list:
    """Run one sample through the full FR-8 chain and return mapped events."""
    return map_events(parse_log_content(content, fmt), rules, config)


def event_by_action(events: list, action: str) -> LogEvent:
    """Return the single event whose event_action equals ``action``."""
    matches = [e for e in events if e.event_action == action]
    assert len(matches) == 1, f"expected exactly one {action!r} event, got {len(matches)}"
    return matches[0]


def evtx_event(events: list, event_id: str) -> LogEvent:
    """Return the EVTX event whose extensions['event_id'] equals ``event_id``."""
    matches = [e for e in events if e.extensions.get("event_id") == event_id]
    assert len(matches) == 1, f"expected exactly one EventID {event_id}, got {len(matches)}"
    return matches[0]


def synthetic_rule(**overrides) -> MappingRule:
    """Build a MappingRule with contract-valid defaults for engine controls."""
    kwargs = {
        "mapping_id": overrides.pop("mapping_id", "SYN-000"),
        "source_format": overrides.pop("source_format", "evtx"),
        "event_action_re": overrides.pop("event_action_re", None),
        "ext_keys": overrides.pop("ext_keys", ()),
        "ext_value_re": overrides.pop("ext_value_re", None),
        "match_type": overrides.pop("match_type", "regex"),
        "is_core": overrides.pop("is_core", True),
        "technique_id": overrides.pop("technique_id", "T1110"),
        "tactic": overrides.pop("tactic", "credential-access"),
        "base_confidence": overrides.pop("base_confidence", 0.7),
        "visibility_hint": overrides.pop("visibility_hint", 3),
        "evidence_ref": overrides.pop("evidence_ref", "synthetic"),
        "sigma_rule_id": overrides.pop("sigma_rule_id", None),
        "notes": overrides.pop("notes", ""),
    }
    assert not overrides, f"unknown MappingRule overrides: {sorted(overrides)}"
    return MappingRule(**kwargs)


class TestCuratedMappingSetLoads:
    """The curated CSV loads cleanly and honors the documented core split."""

    def test_loads_all_83_rows_with_m001_m020_core(self, rules):
        assert len(rules) == 83
        mapping_ids = [r.mapping_id for r in rules]
        assert len(set(mapping_ids)) == 83
        core = {r.mapping_id for r in rules if r.is_core}
        assert core == {f"M{i:03d}" for i in range(1, 21)}

    def test_mapping_rules_are_frozen(self, rules):
        with pytest.raises(dataclasses.FrozenInstanceError):
            rules[0].technique_id = "T9999"


class TestFr8WindowsEventLogEndToEnd:
    """sample.evtx.xml through parser + curated mappings."""

    def test_parse_fidelity(self):
        events = parse_log_content(read_sample("sample.evtx.xml"), "evtx")
        assert len(events) == 4
        assert all(e.source_format == "evtx" for e in events)
        assert all(e.category is None for e in events)
        failed = evtx_event(events, "4625")
        assert failed.event_action == "logon_failure"
        assert failed.username == "administrator"
        assert failed.source_ip == "192.168.1.200"
        created = evtx_event(events, "4688")
        assert created.event_action == "process_created"
        assert created.process_name == "C:\\Windows\\System32\\cmd.exe"

    @pytest.mark.parametrize(
        ("event_id", "expected_ids", "expected_tactics", "expected_confidence"),
        [
            # M001 action tier only (0.6 * 0.85). Extension-keyed rows
            # M010/M039 do NOT fire: a declared action pattern must also
            # match, so account-management rules cannot leak onto logon
            # events merely because TargetUserName exists in EventData.
            (
                "4625",
                {"T1110.001"},
                ["credential-access"],
                0.51,
            ),
            # M003 extension tier on NewProcessName ending in \cmd.exe.
            ("4688", {"T1059.003"}, ["execution"], 0.7),
            # M021 action tier only (0.45 * 0.85); same scoping rationale.
            (
                "4624",
                {"T1078"},
                ["defense-evasion"],
                0.3825,
            ),
            # M009 (0.85) beats M008 (0.68) when deduping T1543.003.
            ("7045", {"T1543.003"}, ["persistence"], 0.85),
        ],
    )
    def test_event_annotation(
        self, rules, event_id, expected_ids, expected_tactics, expected_confidence
    ):
        events = parse_and_map(read_sample("sample.evtx.xml"), "evtx", rules, make_config())
        evt = evtx_event(events, event_id)
        assert evt.datasource_type == "windows:eventlog"
        assert set(evt.attack_technique_ids) == expected_ids
        assert evt.attack_tactics == expected_tactics
        assert evt.detection_confidence == pytest.approx(expected_confidence)


class TestFr8CloudTrailEndToEnd:
    """sample.aws.json through parser + curated mappings."""

    def test_extension_contract(self):
        events = parse_log_content(read_sample("sample.aws.json"), "aws_cloudtrail")
        assert len(events) == 4
        expected_keys = {
            "aws_region",
            "event_source",
            "event_type",
            "error_code",
            "error_message",
            "request_id",
            "user_type",
            "account_id",
            "request_params",
        }
        for evt in events:
            assert set(evt.extensions) == expected_keys

    def test_failed_console_login_maps_to_password_guessing(self, rules):
        events = parse_and_map(read_sample("sample.aws.json"), "aws_cloudtrail", rules, make_config())
        login = event_by_action(events, "ConsoleLogin")
        assert login.datasource_type == "cloud:cloudtrail"
        assert login.attack_technique_ids == ["T1110"]
        assert login.attack_tactics == ["credential-access"]
        # M015 tier 1 on error_code: 0.7 * 1.0
        assert login.detection_confidence == pytest.approx(0.7)

    def test_root_stop_logging_yields_two_defense_evasion_techniques(self, rules):
        events = parse_and_map(read_sample("sample.aws.json"), "aws_cloudtrail", rules, make_config())
        stop = event_by_action(events, "StopLogging")
        # M016 retargeted to the live v19 id (T1562.008 is revoked).
        assert set(stop.attack_technique_ids) == {"T1685.002", "T1078.004"}
        assert stop.attack_tactics == ["defense-evasion"]
        # Highest kept score wins: M016 tier 1 at 0.9 over M049 at 0.7.
        assert stop.detection_confidence == pytest.approx(0.9)

    def test_extension_tier_respects_declared_action_pattern(self, rules):
        """Tier-1 rows fire only when their declared action pattern also passes.

        Extension keys scope WHICH field to inspect; the row's action pattern
        scopes WHICH event the rule applies to. So CreateAccessKey picks up
        M017 (its own action + request_params), while unrelated IAM/S3 events
        sharing those generic extension keys stay unannotated.
        """
        events = parse_and_map(read_sample("sample.aws.json"), "aws_cloudtrail", rules, make_config())

        create_key = event_by_action(events, "CreateAccessKey")
        assert set(create_key.attack_technique_ids) == {"T1098.001"}
        assert create_key.detection_confidence == pytest.approx(0.7)
        assert create_key.attack_tactics == ["persistence"]

        delete_bucket = event_by_action(events, "DeleteBucket")
        assert delete_bucket.attack_technique_ids == []
        assert delete_bucket.detection_confidence == pytest.approx(0.0)


class TestFr8NetworkAndJsonFormats:
    """nginx / LEEF / Zeek / ECS-JSON samples through the chain."""

    def test_nginx_probe_attempts_map_to_t1190(self, rules):
        events = parse_and_map(read_sample("sample.nginx.log"), "nginx", rules, make_config())
        assert len(events) == 6
        assert all(e.datasource_type == "web:access" for e in events)
        by_path = {e.extensions["http_path"]: e for e in events}

        passwd = by_path["/etc/passwd"]
        assert passwd.attack_technique_ids == ["T1190"]
        assert passwd.attack_tactics == ["initial-access"]
        assert passwd.detection_confidence == pytest.approx(0.75)  # M082 tier 1

        for path in ("/wp-admin/login.php", "/.env"):
            probe = by_path[path]
            assert probe.attack_technique_ids == ["T1190"]
            assert probe.detection_confidence == pytest.approx(0.6)  # M083 tier 1

        benign = by_path["/index.html"]
        assert benign.attack_technique_ids == []
        assert benign.detection_confidence == 0.0

    def test_leef_authfail_maps_to_brute_force(self, rules):
        events = parse_and_map(read_sample("sample.leef"), "leef", rules, make_config())
        assert len(events) == 2
        authfail = event_by_action(events, "AuthFail")
        assert authfail.datasource_type == "network:device"
        assert authfail.username == "root"
        assert authfail.attack_technique_ids == ["T1110.001"]
        assert authfail.attack_tactics == ["credential-access"]
        # M079 tier 2 (exact action): 0.5 * 0.85
        assert authfail.detection_confidence == pytest.approx(0.425)

        other = event_by_action(events, "5001")
        assert other.attack_technique_ids == []

    def test_zeek_conn_scan_states_annotate_without_notice_rules(self, rules):
        events = parse_and_map(read_sample("sample.zeek.log"), "zeek", rules, make_config())
        assert len(events) == 4
        assert all(e.datasource_type == "network:zeek" for e in events)
        assert all(e.protocol == "tcp" for e in events[:3])

        # With no notice/http/dns records the only candidate left is the
        # M065 heuristic, which scores at the 0.40 format-level factor
        # because nothing stronger matched these events.
        for scan_like_action in ("REJ", "S0"):
            evt = event_by_action(events, scan_like_action)
            assert evt.attack_technique_ids == ["T1046"]
            assert evt.attack_tactics == ["discovery"]
            assert evt.detection_confidence == pytest.approx(0.18)

        established_events = [e for e in events if e.event_action == "SF"]
        assert len(established_events) == 2
        for evt in established_events:
            assert evt.attack_technique_ids == []
            assert evt.detection_confidence == 0.0

    def test_json_ecs_isolation_from_evtx_rules(self, rules):
        events = parse_and_map(read_sample("sample.json"), "json", rules, make_config())
        assert len(events) == 3
        assert all(e.datasource_type == "generic:json" for e in events)
        assert event_by_action(events, "logon_failure").username == "root"

        # Only json-scoped rows may fire here: M080 is a bare heuristic on
        # the action name (0.45 * 0.40 with nothing stronger matched), and
        # the evtx process_created row (M003) must not leak across formats.
        brute = event_by_action(events, "logon_failure")
        assert brute.attack_technique_ids == ["T1110.001"]
        assert brute.attack_tactics == ["credential-access"]
        assert brute.detection_confidence == pytest.approx(0.18)
        assert event_by_action(events, "deny").attack_technique_ids == []
        assert event_by_action(events, "process_created").attack_technique_ids == []


class TestFr8SyslogFacilityKeyedMapping:
    """Extension tiers key on syslog facility regardless of APP-NAME."""

    def test_facility_alone_does_not_map_without_matching_action(self, rules):
        events = parse_and_map(read_sample("sample.syslog"), "syslog", rules, make_config())
        assert len(events) == 4
        assert all(e.datasource_type == "linux:syslog" for e in events)
        by_action = {e.event_action: e for e in events}
        assert {"nginx", "iptables", "mysqld", "sshd"} == set(by_action)

        # M076 declares BOTH facility=authpriv and an ^sudo... action pattern;
        # tier 1 requires both to pass. The sshd line carries PRI 86
        # (authpriv) but its APP-NAME is sshd, so no annotation fires -
        # a facility key alone must not summon technique T1548.003.
        sshd = by_action["sshd"]
        assert sshd.extensions["facility"] == "authpriv"
        assert sshd.attack_technique_ids == []
        assert sshd.attack_tactics == []
        assert sshd.detection_confidence == pytest.approx(0.0)

        for app in ("nginx", "iptables", "mysqld"):
            evt = by_action[app]
            assert evt.extensions["facility"] != "authpriv"
            assert evt.attack_technique_ids == []
            assert evt.attack_tactics == []
            assert evt.detection_confidence == 0.0


class TestFr8ConfigDrivenSourceEnablement:
    """FR-2 wiring through the repository's real config.yaml."""

    def test_repo_config_shape_matches_contract(self):
        config = load_config(str(REPO_CONFIG))
        assert config["platform_scope"] == "windows"
        assert config["detection_confidence_threshold"] == pytest.approx(0.6)
        assert config["enabled_log_sources"]["cef"] is False
        assert config["enabled_log_sources"]["leef"] is False
        assert config["enabled_log_sources"]["nginx"] is False
        assert config["enabled_log_sources"]["evtx"] is True

    @pytest.mark.parametrize(
        ("sample", "fmt", "expected_datasource"),
        [
            ("sample.cef", "cef", "network:device"),
            ("sample.leef", "leef", "network:device"),
            ("sample.nginx.log", "nginx", "web:access"),
        ],
    )
    def test_disabled_sources_keep_datasource_but_drop_annotations(
        self, rules, sample, fmt, expected_datasource
    ):
        config = load_config(str(REPO_CONFIG))
        events = parse_and_map(read_sample(sample), fmt, rules, config)
        assert events, f"{sample} should parse to at least one event"
        for evt in events:
            assert evt.datasource_type == expected_datasource
            assert evt.attack_technique_ids == []
            assert evt.attack_tactics == []
            assert evt.detection_confidence == 0.0

    def test_enabled_sources_still_annotate_under_repo_config(self, rules):
        config = load_config(str(REPO_CONFIG))
        aws = parse_and_map(read_sample("sample.aws.json"), "aws_cloudtrail", rules, config)
        stop = event_by_action(aws, "StopLogging")
        assert "T1685.002" in stop.attack_technique_ids

        evtx = parse_and_map(read_sample("sample.evtx.xml"), "evtx", rules, config)
        installed = evtx_event(evtx, "7045")
        assert "T1543.003" in installed.attack_technique_ids

    def test_load_config_fills_sane_defaults(self, tmp_path):
        partial = tmp_path / "partial.yaml"
        partial.write_text("platform_scope: windows\n", encoding="utf-8")
        config = load_config(str(partial))
        assert config["platform_scope"] == "windows"
        assert config["detection_confidence_threshold"] == pytest.approx(0.6)
        assert config["enabled_log_sources"] == {fmt: True for fmt in KNOWN_FORMATS}

    def test_missing_config_file_raises_filenotfound(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_config(str(tmp_path / "does_not_exist.yaml"))


class TestMapperEngineControls:
    """Deterministic engine properties pinned with synthetic in-memory rules."""

    def test_score_for_tier_multipliers(self):
        assert score_for_tier(0.6, 1) == pytest.approx(0.6)
        assert score_for_tier(0.6, 2) == pytest.approx(0.51)
        assert score_for_tier(0.6, 3) == pytest.approx(0.24)
        assert score_for_tier(1.0, 3) == pytest.approx(0.4)

    def test_extension_confidence_is_capped_at_095(self):
        rule = synthetic_rule(
            mapping_id="SYN-CAP",
            ext_keys=("imagepath",),
            base_confidence=1.0,
            technique_id="T1543.003",
            tactic="persistence",
        )
        event = LogEvent(source_format="evtx", extensions={"imagepath": "C:\\Temp\\x.exe"})
        mapped = map_log_event(event, [rule], make_config())
        assert mapped.attack_technique_ids == ["T1543.003"]
        assert mapped.detection_confidence == pytest.approx(0.95)

    def test_exact_action_rule_scores_tier2_multiplier(self):
        rule = synthetic_rule(
            mapping_id="SYN-T2",
            event_action_re=re.compile(r"^audit_log_cleared$"),
            match_type="exact",
            base_confidence=0.95,
            technique_id="T1070.001",
            tactic="defense-evasion",
        )
        event = LogEvent(source_format="evtx", event_action="audit_log_cleared")
        mapped = map_log_event(event, [rule], make_config())
        assert mapped.attack_technique_ids == ["T1070.001"]
        assert mapped.detection_confidence == pytest.approx(0.8075)

    def test_extension_tier_requires_declared_action_pattern_to_match(self):
        """Tier 1 enforces BOTH checks when a rule declares ext_keys + action."""
        rule = synthetic_rule(
            mapping_id="SYN-T1",
            event_action_re=re.compile(r"^never_matches$"),
            ext_keys=("targetusername",),
            base_confidence=0.9,
            technique_id="T9001",
            tactic="discovery",
        )
        event = LogEvent(
            source_format="evtx",
            event_action="logon_failure",
            extensions={"targetusername": "bob"},
        )
        mapped = map_log_event(event, [rule], make_config())
        assert mapped.attack_technique_ids == []
        assert mapped.detection_confidence == pytest.approx(0.0)

    def test_extension_tier_fires_when_both_declared_checks_pass(self):
        rule = synthetic_rule(
            mapping_id="SYN-T1B",
            event_action_re=re.compile(r"^logon_failure$"),
            ext_keys=("targetusername",),
            base_confidence=0.9,
            technique_id="T9002",
            tactic="discovery",
        )
        event = LogEvent(
            source_format="evtx",
            event_action="logon_failure",
            extensions={"targetusername": "bob"},
        )
        mapped = map_log_event(event, [rule], make_config())
        assert mapped.attack_technique_ids == ["T9002"]
        assert mapped.detection_confidence == pytest.approx(0.9)

    def test_dedupe_keeps_highest_score_and_tactics_are_sorted_union(self):
        ext_rule = synthetic_rule(
            mapping_id="SYN-EXT",
            ext_keys=("error_code",),
            ext_value_re=re.compile(r".+"),
            technique_id="T1110",
            tactic="credential-access",
            base_confidence=0.7,
        )
        action_rule = synthetic_rule(
            mapping_id="SYN-ACT",
            event_action_re=re.compile(r"^logon_failure$"),
            match_type="exact",
            technique_id="T1078",
            tactic="defense-evasion",
            base_confidence=1.0,
        )
        event = LogEvent(
            source_format="evtx",
            event_action="logon_failure",
            extensions={"error_code": "0xC000006A"},
        )
        mapped = map_log_event(event, [ext_rule, action_rule], make_config())
        assert set(mapped.attack_technique_ids) == {"T1110", "T1078"}
        assert mapped.attack_tactics == ["credential-access", "defense-evasion"]
        # Best kept score: action rule at 1.0 * 0.85.
        assert mapped.detection_confidence == pytest.approx(0.85)


class TestParserAdapterDispatch:
    """parse_log_content dispatch and failure mode."""

    def test_unknown_format_raises_value_error(self):
        with pytest.raises(ValueError):
            parse_log_content("anything", "definitely_not_a_format")

    def test_map_events_preserves_identity_and_length(self, rules):
        events = parse_log_content(read_sample("sample.zeek.log"), "zeek")
        mapped = map_events(events, rules, make_config())
        assert mapped is not events
        assert len(mapped) == len(events)
        assert all(a is b for a, b in zip(mapped, events))
        assert all(e.datasource_type == "network:zeek" for e in mapped)


@pytest.fixture(scope="module")
def rules():
    """Load the curated 83-row mapping set once per module."""
    loaded = load_mappings(str(MAPPINGS_CSV))
    logger.info("Loaded %d mapping rules from %s", len(loaded), MAPPINGS_CSV.name)
    return loaded
