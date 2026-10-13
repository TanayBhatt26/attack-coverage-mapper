"""Tests for parser.mappings_io: CSV loading, validation, and dedup semantics.

Covers the shared-interface contract for ``MappingRule`` / ``load_mappings``:
column parsing and typing, optional-pattern compilation, enum/range
validation with ValueErrors naming the offending mapping_id, duplicate
mapping_id rejection, and preservation of multiple rules per technique_id
(technique-level dedup happens downstream in the matching engine, never at
load time).
"""

import csv
import re
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from parser.mappings_io import MappingRule, load_mappings

REPO_ROOT = Path(__file__).resolve().parents[1]
CURATED_CSV = REPO_ROOT / "data" / "attack_mappings.csv"

ALLOWED_FORMATS = frozenset(
    {"syslog", "cef", "leef", "json", "evtx", "aws_cloudtrail", "nginx", "zeek"}
)
MATCH_TYPES = frozenset({"exact", "regex", "exists", "heuristic"})
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

# Curated file facts: 83 rows M001..M020 is_core=true.
CORE_IDS = [f"M{i:03d}" for i in range(1, 21)]
ALL_IDS = [f"M{i:03d}" for i in range(1, 84)]

FIELDS = [
    "mapping_id",
    "source_format",
    "event_action_pattern",
    "ext_keys",
    "ext_value_pattern",
    "match_type",
    "is_core",
    "technique_id",
    "tactic",
    "base_confidence",
    "visibility_hint",
    "evidence_ref",
    "sigma_rule_id",
    "notes",
]


def _row(**overrides) -> dict:
    """Return one fully-valid CSV row dict with per-test overrides."""
    row = {
        "mapping_id": "M9001",
        "source_format": "evtx",
        "event_action_pattern": "^logon_failure$",
        "ext_keys": "",
        "ext_value_pattern": "",
        "match_type": "exact",
        "is_core": "true",
        "technique_id": "T1110.001",
        "tactic": "credential-access",
        "base_confidence": "0.6",
        "visibility_hint": "3",
        "evidence_ref": "https://attack.mitre.org/techniques/T1110/001/",
        "sigma_rule_id": "",
        "notes": "synthetic row",
    }
    row.update(overrides)
    return row


def _write_csv(tmp_path: Path, *rows: dict) -> str:
    """Write row dicts to a temp CSV with the 14-column header; return path."""
    path = tmp_path / "mappings.csv"
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(FIELDS)
        for row in rows:
            writer.writerow([row.get(field, "") for field in FIELDS])
    return str(path)


def _make_rule(**overrides) -> MappingRule:
    """Build a valid MappingRule directly for dataclass-level tests."""
    values = dict(
        mapping_id="M9001",
        source_format="evtx",
        event_action_re=re.compile(r"^logon_failure$"),
        ext_keys=("targetusername",),
        ext_value_re=None,
        match_type="exists",
        is_core=True,
        technique_id="T1136.001",
        tactic="persistence",
        base_confidence=0.85,
        visibility_hint=4,
        evidence_ref="https://attack.mitre.org/techniques/T1136/001/",
        sigma_rule_id=None,
        notes="direct construction",
    )
    values.update(overrides)
    return MappingRule(**values)


@pytest.mark.unit
class TestMappingRuleDataclass:
    def test_is_frozen(self):
        """MappingRule must be a frozen dataclass; mutation is rejected."""
        rule = _make_rule()
        with pytest.raises(FrozenInstanceError):
            rule.mapping_id = "M9999"

    def test_field_values_roundtrip(self):
        """Every declared field stores exactly what was passed in."""
        action_re = re.compile(r"^process_created$")
        value_re = re.compile(r"(?i)powershell")
        rule = _make_rule(
            event_action_re=action_re,
            ext_keys=("newprocessname",),
            ext_value_re=value_re,
            match_type="regex",
            is_core=False,
            technique_id="T1059.001",
            tactic="execution",
            base_confidence=0.7,
            visibility_hint=3,
            sigma_rule_id="abc-123",
            notes="x;y,z",
        )
        assert rule.event_action_re is action_re
        assert rule.ext_keys == ("newprocessname",)
        assert rule.ext_value_re is value_re
        assert rule.match_type == "regex"
        assert rule.is_core is False
        assert rule.technique_id == "T1059.001"
        assert rule.tactic == "execution"
        assert rule.base_confidence == pytest.approx(0.7)
        assert rule.visibility_hint == 3
        assert rule.sigma_rule_id == "abc-123"
        assert rule.notes == "x;y,z"


@pytest.mark.integration
class TestLoadCuratedCsv:
    def test_row_count_and_file_order_preserved(self):
        rules = load_mappings(str(CURATED_CSV))
        assert [r.mapping_id for r in rules] == ALL_IDS

    def test_core_flags_match_curated_set(self):
        rules = load_mappings(str(CURATED_CSV))
        core = [r.mapping_id for r in rules if r.is_core]
        non_core = [r.mapping_id for r in rules if not r.is_core]
        assert core == CORE_IDS
        assert len(non_core) == 63

    def test_every_row_satisfies_contract_invariants(self):
        for rule in load_mappings(str(CURATED_CSV)):
            assert rule.source_format in ALLOWED_FORMATS, rule.mapping_id
            assert TECHNIQUE_RE.fullmatch(rule.technique_id), rule.mapping_id
            assert rule.match_type in MATCH_TYPES, rule.mapping_id
            assert 0.0 <= rule.base_confidence <= 1.0, rule.mapping_id
            assert isinstance(rule.visibility_hint, int), rule.mapping_id
            assert 0 <= rule.visibility_hint <= 4, rule.mapping_id
            assert isinstance(rule.ext_keys, tuple), rule.mapping_id
            assert all(k == k.lower() for k in rule.ext_keys), rule.mapping_id
            assert (
                rule.event_action_re is None
                or isinstance(rule.event_action_re, re.Pattern)
            ), rule.mapping_id
            assert (
                rule.ext_value_re is None or isinstance(rule.ext_value_re, re.Pattern)
            ), rule.mapping_id

    def test_techniques_repeat_across_rules_without_load_time_dedup(self):
        """Multiple rules may target one technique; loader must keep them all.

        The matching engine owns technique-level dedup (highest score wins);
        the loader only rejects duplicate mapping_ids.
        """
        rules = load_mappings(str(CURATED_CSV))
        techniques = {r.technique_id for r in rules}
        assert len(rules) == 83
        assert len(techniques) < len(rules)

    def test_m049_empty_action_and_typed_ext_cells(self):
        rules = {r.mapping_id: r for r in load_mappings(str(CURATED_CSV))}
        m049 = rules["M049"]
        assert m049.event_action_re is None
        assert m049.ext_keys == ("user_type",)
        assert m049.ext_value_re is not None
        assert m049.ext_value_re.pattern == r"^Root$"

    def test_m024_multi_key_ext_keys_lowercased(self):
        rules = {r.mapping_id: r for r in load_mappings(str(CURATED_CSV))}
        assert rules["M024"].ext_keys == ("substatus", "status")

    def test_sigma_rule_id_optional(self):
        rules = {r.mapping_id: r for r in load_mappings(str(CURATED_CSV))}
        assert rules["M001"].sigma_rule_id is None
        assert rules["M005"].sigma_rule_id == "92626ddd-662c-49e3-ac59-f6535f12d189"

    def test_numeric_fields_are_typed(self):
        rules = {r.mapping_id: r for r in load_mappings(str(CURATED_CSV))}
        m001 = rules["M001"]
        assert isinstance(m001.base_confidence, float)
        assert m001.base_confidence == pytest.approx(0.6)
        assert m001.visibility_hint == 3


@pytest.mark.integration
class TestSyntheticLoading:
    def test_empty_optional_cells_become_none(self, tmp_path):
        path = _write_csv(tmp_path, _row(event_action_pattern="", ext_value_pattern=""))
        (rule,) = load_mappings(path)
        assert rule.event_action_re is None
        assert rule.ext_value_re is None
        assert rule.ext_keys == ()

    def test_ext_keys_whitespace_split_and_lowercased(self, tmp_path):
        path = _write_csv(tmp_path, _row(ext_keys="LogonType IpAddress"))
        (rule,) = load_mappings(path)
        assert rule.ext_keys == ("logontype", "ipaddress")

    def test_single_ext_key_lowercased(self, tmp_path):
        path = _write_csv(tmp_path, _row(ext_keys="NewProcessName"))
        (rule,) = load_mappings(path)
        assert rule.ext_keys == ("newprocessname",)

    @pytest.mark.parametrize("cell,expected", [("TRUE", True), ("False", False), ("true", True)])
    def test_is_core_case_insensitive(self, tmp_path, cell, expected):
        path = _write_csv(tmp_path, _row(is_core=cell))
        (rule,) = load_mappings(path)
        assert rule.is_core is expected

    def test_all_eight_source_formats_accepted(self, tmp_path):
        rows = [
            _row(mapping_id=f"M9{i:02d}", source_format=fmt)
            for i, fmt in enumerate(sorted(ALLOWED_FORMATS), start=1)
        ]
        path = _write_csv(tmp_path, *rows)
        rules = load_mappings(path)
        assert len(rules) == len(ALLOWED_FORMATS)
        assert {r.source_format for r in rules} == ALLOWED_FORMATS

    def test_commas_and_semicolons_in_notes_survive_roundtrip(self, tmp_path):
        path = _write_csv(tmp_path, _row(notes="failed logon; password-guessing prior, v2"))
        (rule,) = load_mappings(path)
        assert rule.notes == "failed logon; password-guessing prior, v2"

    def test_boundary_confidence_and_visibility_accepted(self, tmp_path):
        rows = [
            _row(mapping_id="M9101", base_confidence="0.0", visibility_hint="0"),
            _row(mapping_id="M9102", base_confidence="1.0", visibility_hint="4"),
        ]
        rules = load_mappings(_write_csv(tmp_path, *rows))
        assert [r.base_confidence for r in rules] == pytest.approx([0.0, 1.0])
        assert [r.visibility_hint for r in rules] == [0, 4]

    def test_missing_file_raises_filenotfound(self, tmp_path):
        missing = str(tmp_path / "nope.csv")
        with pytest.raises(FileNotFoundError):
            load_mappings(missing)

    def test_repeated_technique_ids_kept_verbatim(self, tmp_path):
        rows = [
            _row(mapping_id="M9201", technique_id="T1053.005"),
            _row(mapping_id="M9202", technique_id="T1053.005"),
            _row(mapping_id="M9203", technique_id="T1053.005"),
        ]
        rules = load_mappings(_write_csv(tmp_path, *rows))
        assert [r.mapping_id for r in rules] == ["M9201", "M9202", "M9203"]
        assert all(r.technique_id == "T1053.005" for r in rules)


@pytest.mark.integration
class TestValidationErrors:
    @pytest.mark.parametrize("fmt", ["wineventlog", "AWS_CloudTrail", ""])
    def test_unknown_source_format_raises(self, tmp_path, fmt):
        path = _write_csv(tmp_path, _row(source_format=fmt))
        with pytest.raises(ValueError) as excinfo:
            load_mappings(path)
        assert "M9001" in str(excinfo.value)

    def test_bad_event_action_regex_raises(self, tmp_path):
        path = _write_csv(tmp_path, _row(event_action_pattern="[unclosed"))
        with pytest.raises(ValueError) as excinfo:
            load_mappings(path)
        assert "M9001" in str(excinfo.value)

    def test_bad_ext_value_regex_raises(self, tmp_path):
        path = _write_csv(
            tmp_path,
            _row(ext_keys="sharename", ext_value_pattern="(unclosed"),
        )
        with pytest.raises(ValueError) as excinfo:
            load_mappings(path)
        assert "M9001" in str(excinfo.value)

    @pytest.mark.parametrize(
        "bad_id",
        ["T123", "T12345", "t1110", "T1110.0001", "", "ATTACK1", "T1110."],
    )
    def test_bad_technique_id_raises(self, tmp_path, bad_id):
        path = _write_csv(tmp_path, _row(technique_id=bad_id))
        with pytest.raises(ValueError) as excinfo:
            load_mappings(path)
        assert "M9001" in str(excinfo.value)

    def test_duplicate_mapping_id_raises_naming_it(self, tmp_path):
        path = _write_csv(
            tmp_path,
            _row(mapping_id="M9001"),
            _row(mapping_id="M9001", technique_id="T1078"),
        )
        with pytest.raises(ValueError) as excinfo:
            load_mappings(path)
        assert "M9001" in str(excinfo.value)

    @pytest.mark.parametrize("value", ["1.2", "-0.05", "2"])
    def test_base_confidence_out_of_range_raises(self, tmp_path, value):
        path = _write_csv(tmp_path, _row(base_confidence=value))
        with pytest.raises(ValueError):
            load_mappings(path)

    @pytest.mark.parametrize("value", ["5", "-1"])
    def test_visibility_hint_out_of_range_raises(self, tmp_path, value):
        path = _write_csv(tmp_path, _row(visibility_hint=value))
        with pytest.raises(ValueError):
            load_mappings(path)

    def test_invalid_match_type_raises(self, tmp_path):
        path = _write_csv(tmp_path, _row(match_type="fuzzy"))
        with pytest.raises(ValueError) as excinfo:
            load_mappings(path)
        assert "M9001" in str(excinfo.value)
