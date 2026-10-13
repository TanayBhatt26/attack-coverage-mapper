"""Unit tests for the LogEvent bridge dataclass (parser.log_event_bridge).

Pins the shared Wave-2 interface contract: the exact core field set with its
defaults, per-instance mutable defaults, uuid4-based event ids, and the
mapper-facing enrichment attributes that must exist immediately after init.
"""

import uuid
from dataclasses import fields
from typing import Set

import pytest

from parser.log_event_bridge import LogEvent

pytestmark = pytest.mark.unit

# Core schema exactly as contracted (declaration order preserved here).
CORE_FIELDS = (
    "event_id",
    "timestamp",
    "source_format",
    "source_host",
    "source_ip",
    "source_port",
    "dest_ip",
    "dest_port",
    "event_type",
    "event_action",
    "severity",
    "severity_code",
    "category",
    "username",
    "user_id",
    "process_name",
    "process_id",
    "protocol",
    "bytes_in",
    "bytes_out",
    "message",
    "raw",
    "extensions",
)

# Core fields that are Optional and therefore must default to None.
OPTIONAL_NONE_FIELDS: Set[str] = set(CORE_FIELDS) - {
    "event_id",
    "source_format",
    "extensions",
}

# Enrichment annotations attached post-init for the attack mapper. They may be
# declared as dataclass fields or plain post-init attributes; tests only rely
# on attribute access semantics, which both satisfy.
ENRICHMENT_FIELDS = (
    "attack_technique_ids",
    "attack_tactics",
    "datasource_type",
    "detection_confidence",
)


def _field_names(model: type) -> Set[str]:
    """Return the declared dataclass field names of ``model``."""
    return {f.name for f in fields(model)}


def test_core_schema_matches_contract():
    """Every contracted core field is declared, and nothing unlisted is added."""
    names = _field_names(LogEvent)
    for name in CORE_FIELDS:
        assert name in names, f"missing contracted field: {name}"
    extra = names - set(CORE_FIELDS) - set(ENRICHMENT_FIELDS)
    assert extra == set(), f"unexpected extra fields: {sorted(extra)}"


def test_defaults_on_empty_construction():
    """LogEvent() yields a uuid4 string id, 'unknown' format, and blank fields."""
    event = LogEvent()
    parsed = uuid.UUID(event.event_id)  # raises unless a canonical UUID string
    assert parsed.version == 4
    assert str(parsed) == event.event_id
    assert event.source_format == "unknown"
    for name in sorted(OPTIONAL_NONE_FIELDS):
        assert getattr(event, name) is None, f"{name} should default to None"
    assert event.extensions == {}


def test_event_ids_unique_per_instance():
    """Each instance receives its own freshly generated event_id."""
    first, second = LogEvent(), LogEvent()
    assert first.event_id != second.event_id


def test_explicit_event_id_overrides_default():
    """A caller-supplied event_id wins over the uuid4 default factory."""
    fixed_id = "11111111-2222-3333-4444-555555555555"
    event = LogEvent(event_id=fixed_id)
    assert event.event_id == fixed_id


def test_extensions_default_is_per_instance():
    """Extension dicts are never shared between instances."""
    first = LogEvent()
    first.extensions["event_id"] = 4625
    second = LogEvent()
    assert second.extensions == {}


def test_enrichment_attributes_default_clean():
    """Enrichment attrs exist right after init with neutral defaults."""
    event = LogEvent()
    assert event.attack_technique_ids == []
    assert event.attack_tactics == []
    assert event.datasource_type is None
    assert isinstance(event.detection_confidence, float)
    assert event.detection_confidence == 0.0


def test_enrichment_lists_are_per_instance():
    """Annotation lists on one event never leak into another instance."""
    first = LogEvent()
    first.attack_technique_ids.append("T1110.001")
    first.attack_tactics.append("credential-access")
    second = LogEvent()
    assert second.attack_technique_ids == []
    assert second.attack_tactics == []


def test_mapper_style_annotation_mutation():
    """Annotations written mapper-style stick on the annotated instance."""
    event = LogEvent(source_format="syslog")
    event.attack_technique_ids.extend(["T1110.001", "T1110.003"])
    event.attack_tactics.append("credential-access")
    event.datasource_type = "linux:syslog"
    event.detection_confidence = 0.85
    assert event.attack_technique_ids == ["T1110.001", "T1110.003"]
    assert event.attack_tactics == ["credential-access"]
    assert event.datasource_type == "linux:syslog"
    assert event.detection_confidence == 0.85


def test_all_core_fields_round_trip_via_keywords():
    """Every contracted field accepts and returns the value it was given."""
    payload = dict(
        timestamp="2026-08-26T10:00:00Z",
        source_format="evtx",
        source_host="WIN-DC01",
        source_ip="10.0.0.5",
        source_port=49152,
        dest_ip="192.168.1.10",
        dest_port=445,
        event_type="audit",
        event_action="logon_failure",
        severity="high",
        severity_code=8,
        category="account-logon",
        username="jdoe",
        user_id="S-1-5-21-1004336348-1177238915-682003330-500",
        process_name="powershell.exe",
        process_id=4692,
        protocol="tcp",
        bytes_in=1024,
        bytes_out=4096,
        message="An account failed to log on.",
        raw="<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'/>",
    )
    event = LogEvent(**payload)
    for name, value in payload.items():
        assert getattr(event, name) == value, f"{name} did not round-trip"


def test_extensions_accept_arbitrary_nested_values():
    """extensions behaves as Dict[str, Any]: nested structures pass through."""
    nested = {
        "event_id": 7045,
        "EventData": {"ServiceName": "Sysmon", "Paths": ["C:\\a.exe", "C:\\b.exe"]},
        "tags": ["detection", "windows"],
        "ratio": 0.75,
    }
    event = LogEvent(extensions=nested)
    assert event.extensions == nested


def test_unknown_keyword_is_rejected():
    """Misspelled parser kwargs raise TypeError instead of vanishing."""
    with pytest.raises(TypeError):
        LogEvent(source_formats="evtx")
