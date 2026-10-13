"""conftest.py -- Shared pytest fixtures and synthetic LogEvent builders.

Test-wide infrastructure for the ATT&CK Coverage Mapper suite:

- ``make_log_event`` plus per-format builders that produce contract-faithful
  synthetic :class:`~parser.log_event_bridge.LogEvent` objects for all eight
  supported formats (``evtx``, ``syslog``, ``cef``, ``leef``, ``json``,
  ``aws_cloudtrail``, ``nginx``, ``zeek``) without going through any parser.
- ``build_mapping_rule`` (exposed as the ``make_mapping_rule`` fixture) for
  constructing ``parser.mappings_io.MappingRule`` instances without
  hand-compiling regexes or inventing required boilerplate fields.
- Factories writing temporary ``config.yaml`` and mapping CSV files via
  ``tmp_path`` (stdlib-only YAML rendering).
- Constants resolving the real sample logs under ``data/sample_logs``.

Everything here is offline; only pytest itself is needed beyond the project
package. Because ``tests/`` is a package (``__init__.py``), helpers may also
be imported directly, e.g. ``from tests.conftest import make_evtx_event``.
"""

from __future__ import annotations

import copy
import csv
import itertools
import json
import logging
import re
from dataclasses import fields as dataclass_fields
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

import pytest

from config_loader import DEFAULT_CONFIG
from parser.log_event_bridge import LogEvent, normalize_severity
from parser.mappings_io import MappingRule

# Phase 5 hunt-query fixtures (sigma_clone builder). Re-export the fixture
# here so pytest discovers it (fixtures are only auto-collected from
# conftest.py and plugins, not from plain imported modules).
from tests.fixtures_hunt import sigma_clone  # noqa: F401

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_LOGS_DIR = REPO_ROOT / "data" / "sample_logs"

#: Every log format the parsers/mapper support, in canonical order.
LOG_FORMATS: tuple[str, ...] = (
    "evtx",
    "syslog",
    "cef",
    "leef",
    "json",
    "aws_cloudtrail",
    "nginx",
    "zeek",
)

#: Canonical filenames of the real sample logs, keyed by format.
SAMPLE_LOG_FILENAMES: dict[str, str] = {
    "evtx": "sample.evtx.xml",
    "aws_cloudtrail": "sample.aws.json",
    "json": "sample.json",
    "syslog": "sample.syslog",
    "cef": "sample.cef",
    "leef": "sample.leef",
    "nginx": "sample.nginx.log",
    "zeek": "sample.zeek.log",
}

#: Exact column order of ``data/attack_mappings.csv`` (14 columns).
MAPPING_CSV_COLUMNS: tuple[str, ...] = (
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
)

#: Windows Security event ids -> the ``event_action`` values emitted by the
#: adapted EVTX bridge (the raw id lives only in ``extensions['event_id']``).
EVTX_ACTION_BY_EVENT_ID: dict[int, str] = {
    4624: "logon_success",
    4625: "logon_failure",
    4634: "logoff",
    4648: "explicit_credential_logon",
    4663: "object_access",
    4672: "special_privilege_logon",
    4688: "process_created",
    4689: "process_terminated",
    4698: "task_created",
    4702: "task_modified",
    4720: "user_account_created",
    4726: "user_account_deleted",
    4732: "member_added_to_group",
    4740: "account_locked_out",
    4771: "kerberos_pre_auth_failed",
    4776: "ntlm_auth_attempt",
    5140: "network_share_accessed",
    7036: "service_state_changed",
    7045: "new_service_installed",
    1102: "audit_log_cleared",
}


# ---------------------------------------------------------------------------
# Generic LogEvent builder
# ---------------------------------------------------------------------------

def make_log_event(**overrides: Any) -> LogEvent:
    """Build a synthetic :class:`LogEvent` with neutral defaults.

    Keyword arguments matching a ``LogEvent`` field name are passed to the
    constructor (``source_format`` defaults to ``"unknown"``); anything else
    is attached as an extra attribute after construction. Returns a fresh
    instance every call -- callers may mutate freely without cross-test bleed.
    """
    overrides = dict(overrides)
    source_format = overrides.pop("source_format", "unknown")

    init_names = {f.name for f in dataclass_fields(LogEvent)}
    init_kwargs: dict[str, Any] = {"source_format": source_format}
    extras: dict[str, Any] = {}
    for key, value in overrides.items():
        if key in init_names:
            init_kwargs[key] = value
        else:
            extras[key] = value

    event = LogEvent(**init_kwargs)
    for key, value in extras.items():
        setattr(event, key, value)
    return event


def _apply_severity(kwargs: dict[str, Any], raw_severity: Any) -> None:
    """Fill ``severity``/``severity_code`` consistently via the bridge helper."""
    if raw_severity is None:
        return
    label, code = normalize_severity(raw_severity)
    kwargs.setdefault("severity", label)
    kwargs.setdefault("severity_code", code)


# ---------------------------------------------------------------------------
# Per-format synthetic builders
# ---------------------------------------------------------------------------

def make_syslog_event(
    app: str = "sshd",
    *,
    message: str = (
        "Failed password for invalid user admin from 203.0.113.50 "
        "port 42422 ssh2"
    ),
    severity: str | None = "medium",
    **overrides: Any,
) -> LogEvent:
    """RFC-style syslog event; ``event_action`` is the free-form APP-NAME/TAG."""
    kwargs: dict[str, Any] = {
        "source_format": "syslog",
        "timestamp": "Jan 15 10:00:00",
        "source_host": "linux-web01",
        "event_action": app,
        "message": message,
        "username": "admin",
        "source_ip": "203.0.113.50",
        **overrides,
    }
    _apply_severity(kwargs, severity)
    return make_log_event(**kwargs)


def make_cef_event(
    name: str = "Firewall deny",
    *,
    severity: str | None = "7",
    extensions: Mapping[str, Any] | None = None,
    **overrides: Any,
) -> LogEvent:
    """ArcSight CEF event; ``event_action`` mirrors the CEF ``name`` field."""
    kwargs: dict[str, Any] = {
        "source_format": "cef",
        "timestamp": "2026-01-15T10:00:00.000Z",
        "source_host": "fw-edge01",
        "source_ip": "203.0.113.50",
        "dest_ip": "10.0.0.25",
        "dest_port": 22,
        "protocol": "tcp",
        "event_type": "firewall",
        "event_action": name,
        "message": f"CEF synthetic event: {name}",
        "extensions": {
            "act": "block",
            "cs1": "edge-policy",
            "cs1Label": "policy",
            **(dict(extensions) if extensions else {}),
        },
        **overrides,
    }
    _apply_severity(kwargs, severity)
    return make_log_event(**kwargs)


def make_leef_event(
    event_name: str = "Firewall deny",
    *,
    severity: str | None = "4",
    extensions: Mapping[str, Any] | None = None,
    **overrides: Any,
) -> LogEvent:
    """IBM LEEF event; ``event_action`` mirrors the LEEF event name field."""
    kwargs: dict[str, Any] = {
        "source_format": "leef",
        "timestamp": "2026-01-15T10:00:00.000Z",
        "source_host": "qradar-sensor01",
        "source_ip": "203.0.113.75",
        "dest_ip": "10.0.0.30",
        "dest_port": 445,
        "protocol": "tcp",
        "event_type": "firewall",
        "event_action": event_name,
        "message": f"LEEF synthetic event: {event_name}",
        "extensions": {
            "cat": "network",
            "identHostName": "srv-files01",
            **(dict(extensions) if extensions else {}),
        },
        **overrides,
    }
    _apply_severity(kwargs, severity)
    return make_log_event(**kwargs)


def make_json_event(
    action: str = "network_connection",
    *,
    extensions: Mapping[str, Any] | None = None,
    **overrides: Any,
) -> LogEvent:
    """Generic JSON/ECS-shaped event (as produced by the JSON/NDJSON parser)."""
    kwargs: dict[str, Any] = {
        "source_format": "json",
        "timestamp": "2026-01-15T10:00:00.000Z",
        "source_host": "elastic-node01",
        "source_ip": "192.0.2.10",
        "dest_ip": "198.51.100.20",
        "dest_port": 443,
        "protocol": "tcp",
        "event_type": "network",
        "event_action": action,
        "message": "Synthetic ECS-style JSON event",
        "extensions": {
            "ecs": {"version": "8.11.0"},
            "agent": {"name": "synthetic-agent"},
            **(dict(extensions) if extensions else {}),
        },
        **overrides,
    }
    return make_log_event(**kwargs)


def make_evtx_event(
    windows_event_id: int | None = None,
    *,
    event_action: str | None = None,
    extensions: Mapping[str, Any] | None = None,
    **overrides: Any,
) -> LogEvent:
    """Windows Security event shaped exactly like the adapted EVTX bridge.

    ``windows_event_id`` is stored only in ``extensions['event_id']`` (never
    promoted to a top-level field) and derives ``event_action`` from
    :data:`EVTX_ACTION_BY_EVENT_ID` unless ``event_action`` is explicit.
    EventData keys are merged verbatim (original casing preserved);
    ``category`` stays ``None`` because the EVTX bridge never populates it.
    """
    merged_extensions: dict[str, Any] = {}
    derived_action: str | None = None
    if windows_event_id is not None:
        merged_extensions["event_id"] = int(windows_event_id)
        derived_action = EVTX_ACTION_BY_EVENT_ID.get(int(windows_event_id))
    if extensions:
        merged_extensions.update(dict(extensions))

    kwargs: dict[str, Any] = {
        "source_format": "evtx",
        "timestamp": "2026-01-15T10:00:00.000Z",
        "source_host": "WIN-DC01",
        "event_action": event_action if event_action is not None else derived_action,
        "extensions": merged_extensions,
        "category": None,
        **overrides,
    }
    return make_log_event(**kwargs)


def make_evtx_logon_failure(**overrides: Any) -> LogEvent:
    """Failed interactive logon (id 4625) with typical EventData fields."""
    overrides.setdefault(
        "extensions",
        {
            "LogonType": "10",
            "TargetUserName": "administrator",
            "WorkstationName": "ATTACKER-PC",
            "IpAddress": "203.0.113.50",
            "Status": "0xC000006A",
        },
    )
    overrides.setdefault("username", "administrator")
    return make_evtx_event(4625, **overrides)


def make_evtx_process_creation(**overrides: Any) -> LogEvent:
    """Process creation (id 4688); ``NewProcessName`` supports tier-1 rules."""
    overrides.setdefault(
        "extensions",
        {
            "SubjectUserName": "jdoe",
            "NewProcessName": "C:\\\\Windows\\\\System32\\\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
            "ProcessId": "0x12ac",
        },
    )
    overrides.setdefault("username", "jdoe")
    overrides.setdefault("process_name", "cmd.exe")
    return make_evtx_event(4688, **overrides)


_CLOUDTRAIL_EXTENSION_DEFAULTS: dict[str, Any] = {
    "aws_region": "us-east-1",
    "event_source": "signin.amazonaws.com",
    "event_type": "AwsConsoleSignIn",
    "error_code": "",
    "error_message": "",
    "request_id": "synthetic-request-id",
    "user_type": "IAMUser",
    "account_id": "123456789012",
    "request_params": {},
}


def make_cloudtrail_event(
    event_name: str = "ConsoleLogin",
    *,
    request_params: Mapping[str, Any] | None = None,
    extensions: Mapping[str, Any] | None = None,
    **overrides: Any,
) -> LogEvent:
    """AWS CloudTrail event; ``event_action`` is ``eventName`` verbatim.

    The nine documented extension keys are always present (matching the
    adapted CloudTrail parser); ``extensions``/``request_params`` overlay
    their defaults.
    """
    merged = dict(_CLOUDTRAIL_EXTENSION_DEFAULTS)
    if request_params is not None:
        merged["request_params"] = dict(request_params)
    if extensions:
        merged.update(dict(extensions))

    return make_log_event(
        source_format="aws_cloudtrail",
        timestamp="2026-01-15T10:00:00Z",
        source_ip="203.0.113.10",
        event_type="AwsConsoleSignIn",
        event_action=event_name,
        extensions=merged,
        **overrides,
    )


def make_cloudtrail_failed_console_login(**overrides: Any) -> LogEvent:
    """Root console sign-in rejected with ``Failed authentication``."""
    return make_cloudtrail_event(
        "ConsoleLogin",
        extensions={
            "error_code": "Failed authentication",
            "error_message": "Failed authentication",
            "user_type": "Root",
        },
        **overrides,
    )


def make_cloudtrail_stop_logging(**overrides: Any) -> LogEvent:
    """Root disabling CloudTrail logging (``StopLogging``) -- defense evasion."""
    return make_cloudtrail_event(
        "StopLogging",
        extensions={
            "event_source": "cloudtrail.amazonaws.com",
            "event_type": "AwsApiCall",
            "user_type": "Root",
        },
        username="arn:aws:sts::123456789012:assumed-role/RootSession",
        **overrides,
    )


def make_nginx_event(
    method: str = "POST",
    status_code: int = 401,
    *,
    path: str = "/wp-login.php",
    extensions: Mapping[str, Any] | None = None,
    **overrides: Any,
) -> LogEvent:
    """Access-log event; ``event_action`` is ``'<METHOD> <status>'``."""
    return make_log_event(
        source_format="nginx",
        timestamp="15/Jan/2026:10:00:00 +0000",
        source_host="web-front01",
        source_ip="203.0.113.90",
        dest_port=443,
        protocol="HTTP/1.1",
        bytes_out=567,
        event_type="web_access",
        event_action=f"{method} {status_code}",
        message=f'{method} {path} -> {status_code}',
        extensions={
            "request": path,
            "user_agent": "Mozilla/5.0 (synthetic)",
            "referer": "-",
            **(dict(extensions) if extensions else {}),
        },
        **overrides,
    )


_ZEEK_KINDS: tuple[str, ...] = ("conn", "http", "dns", "notice", "weird")


def make_zeek_event(
    kind: str = "conn",
    *,
    conn_state: str = "S0",
    method: str = "GET",
    status_code: int = 200,
    qtype: str = "TXT",
    note: str = "Scan::Address_Scan",
    extensions: Mapping[str, Any] | None = None,
    **overrides: Any,
) -> LogEvent:
    """Zeek event; ``event_action`` follows the adapted parser's contract.

    ``kind`` selects the Zeek log flavour: ``conn`` -> conn_state code or
    ``'connection'``, ``http`` -> ``'<METHOD> <status>'``, ``dns`` ->
    ``'DNS <qtype> query'``, ``notice`` -> the note enum verbatim,
    ``weird`` -> empty string.
    """
    if kind not in _ZEEK_KINDS:
        raise ValueError(
            f"unknown zeek kind {kind!r}; expected one of {_ZEEK_KINDS}"
        )

    base_extensions: dict[str, Any] = {"uid": "CsynthZeek01"}
    if kind == "conn":
        action: str | None = conn_state if conn_state else "connection"
        base_extensions["conn_state"] = conn_state
    elif kind == "http":
        action = f"{method} {status_code}"
        base_extensions.update({"uri": "/login", "user_agent": "curl/8.0"})
    elif kind == "dns":
        action = f"DNS {qtype} query"
        base_extensions.update(
            {"query": "exfil.example.invalid", "qtype_name": qtype}
        )
    elif kind == "notice":
        action = note
        base_extensions["note"] = note
    else:  # weird
        action = ""
        base_extensions["addl"] = "synthetic-weird"

    base_extensions.update(dict(extensions) if extensions else {})
    return make_log_event(
        source_format="zeek",
        timestamp="2026-01-15T10:00:00.000000",
        source_host="zeek-sensor01",
        source_ip="192.0.2.10",
        dest_ip="198.51.100.20",
        dest_port={"http": 80, "dns": 53}.get(kind, 443),
        protocol="tcp",
        bytes_in=1024,
        bytes_out=512,
        event_type=kind,
        event_action=action,
        message=f"Zeek {kind} synthetic record",
        extensions=base_extensions,
        **overrides,
    )


# ---------------------------------------------------------------------------
# MappingRule / config / CSV helpers
# ---------------------------------------------------------------------------

_mapping_id_counter = itertools.count(1)


def _compile_optional_pattern(
    pattern: str | re.Pattern[str] | None,
) -> re.Pattern[str] | None:
    """Return compiled pattern unchanged; compile raw strings."""
    if pattern is None or isinstance(pattern, re.Pattern):
        return pattern
    return re.compile(pattern)


def build_mapping_rule(
    *,
    mapping_id: str | None = None,
    source_format: str = "evtx",
    event_action_re: str | re.Pattern[str] | None = None,
    ext_keys: str | Iterable[str] = (),
    ext_value_re: str | re.Pattern[str] | None = None,
    match_type: str = "regex",
    is_core: bool = True,
    technique_id: str = "T1059.001",
    tactic: str = "execution",
    base_confidence: float = 0.7,
    visibility_hint: int = 3,
    evidence_ref: str = "https://attack.mitre.org/techniques/T1059/001/",
    sigma_rule_id: str | None = None,
    notes: str = "",
) -> MappingRule:
    """Construct a :class:`MappingRule` with sane, validated-shape defaults.

    Convenience over the raw frozen dataclass: regex fields accept plain
    strings, ``ext_keys`` accepts ``"a;b"`` or any iterable of keys and is
    normalized to a lowercased tuple, and ``mapping_id`` defaults to a unique
    synthetic id (``SYNTH-0001``, ...) so several rules can coexist without
    duplicate-id collisions.
    """
    if isinstance(ext_keys, str):
        normalized_keys = tuple(
            key.strip().lower() for key in ext_keys.split(";") if key.strip()
        )
    else:
        normalized_keys = tuple(str(key).strip().lower() for key in ext_keys)

    return MappingRule(
        mapping_id=mapping_id or f"SYNTH-{next(_mapping_id_counter):04d}",
        source_format=source_format,
        event_action_re=_compile_optional_pattern(event_action_re),
        ext_keys=normalized_keys,
        ext_value_re=_compile_optional_pattern(ext_value_re),
        match_type=match_type,
        is_core=is_core,
        technique_id=technique_id,
        tactic=tactic,
        base_confidence=float(base_confidence),
        visibility_hint=int(visibility_hint),
        evidence_ref=evidence_ref,
        sigma_rule_id=sigma_rule_id,
        notes=notes,
    )


def _mapping_rule_to_row(rule: MappingRule) -> dict[str, str]:
    """Serialize a rule to CSV cells.

    Conventions (documented, not contractual upstream): regex cells carry the
    ``re.Pattern.pattern`` text (empty when absent), ``ext_keys`` is
    ``';'``-joined lowercase, booleans serialize as ``true``/``false``.
    """
    return {
        "mapping_id": rule.mapping_id,
        "source_format": rule.source_format,
        "event_action_pattern": (
            rule.event_action_re.pattern if rule.event_action_re else ""
        ),
        "ext_keys": ";".join(rule.ext_keys),
        "ext_value_pattern": (
            rule.ext_value_re.pattern if rule.ext_value_re else ""
        ),
        "match_type": rule.match_type,
        "is_core": "true" if rule.is_core else "false",
        "technique_id": rule.technique_id,
        "tactic": rule.tactic,
        "base_confidence": str(rule.base_confidence),
        "visibility_hint": str(rule.visibility_hint),
        "evidence_ref": rule.evidence_ref,
        "sigma_rule_id": rule.sigma_rule_id or "",
        "notes": rule.notes,
    }


def _write_mappings_csv(path: Path, rows: Sequence[MappingRule | Mapping[str, Any]]) -> Path:
    """Write ``rows`` as a 14-column mapping CSV at ``path``.

    Rows may be :class:`MappingRule` instances (serialized via
    :func:`_mapping_rule_to_row`) or raw dicts whose keys are column names;
    dict cells are written verbatim so tests control the exact serialization.
    Missing cells become empty strings.
    """
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(MAPPING_CSV_COLUMNS))
        writer.writeheader()
        for index, row in enumerate(rows):
            if isinstance(row, MappingRule):
                cells: dict[str, str] = _mapping_rule_to_row(row)
            else:
                unknown = set(row) - set(MAPPING_CSV_COLUMNS)
                if unknown:
                    logger.debug(
                        "Ignoring non-column keys in CSV row %d: %s",
                        index + 1,
                        sorted(unknown),
                    )
                cells = {
                    column: "" if row.get(column) is None else str(row.get(column, ""))
                    for column in MAPPING_CSV_COLUMNS
                }
            writer.writerow(cells)
    logger.debug("Wrote %d mapping rows to %s", len(rows), path)
    return path


def _yaml_scalar(value: Any) -> str:
    """Render one scalar as a YAML-safe token (stdlib only)."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return repr(value)
    return json.dumps(str(value))


def _render_yaml_block(mapping: Mapping[str, Any], indent: int = 0) -> str:
    """Recursively render a flat-ish mapping as YAML text."""
    pad = "  " * indent
    lines: list[str] = []
    for key, value in mapping.items():
        if isinstance(value, Mapping):
            lines.append(f"{pad}{key}:")
            lines.append(_render_yaml_block(value, indent + 1))
        else:
            lines.append(f"{pad}{key}: {_yaml_scalar(value)}")
    return "\n".join(lines)


def render_config_yaml(config: Mapping[str, Any]) -> str:
    """Render a config mapping (``platform_scope`` / threshold / sources)."""
    return _render_yaml_block(config)


def _write_config_yaml(path: Path, config: Mapping[str, Any]) -> Path:
    """Write ``config`` as YAML at ``path`` and return the path."""
    path.write_text(render_config_yaml(config) + "\n", encoding="utf-8")
    logger.debug("Wrote config to %s", path)
    return path


def _default_config() -> dict[str, Any]:
    """Fresh deep copy of the loader's canonical defaults (all sources on)."""
    return copy.deepcopy(DEFAULT_CONFIG)


# ---------------------------------------------------------------------------
# Sample log path resolution
# ---------------------------------------------------------------------------

def resolve_sample_log_path(fmt: str) -> Path:
    """Resolve the real sample-log file for ``fmt`` under ``data/sample_logs``.

    Raises ``ValueError`` for an unsupported format and ``FileNotFoundError``
    if the expected file has not been copied into place.
    """
    try:
        filename = SAMPLE_LOG_FILENAMES[fmt]
    except KeyError:
        raise ValueError(
            f"unknown log format {fmt!r}; expected one of {sorted(SAMPLE_LOG_FILENAMES)}"
        ) from None
    path = SAMPLE_LOGS_DIR / filename
    if not path.is_file():
        raise FileNotFoundError(f"sample log missing for {fmt!r}: {path}")
    return path


# ---------------------------------------------------------------------------
# pytest fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def make_mapping_rule() -> Callable[..., MappingRule]:
    """Factory fixture around :func:`build_mapping_rule`."""
    return build_mapping_rule


@pytest.fixture(name="make_log_event")
def _make_log_event_factory() -> Callable[..., LogEvent]:
    """Factory fixture exposing :func:`make_log_event` to tests."""
    return make_log_event


@pytest.fixture(name="make_syslog_event")
def _make_syslog_event_factory() -> Callable[..., LogEvent]:
    """Factory fixture around :func:`make_syslog_event`."""
    return make_syslog_event


@pytest.fixture(name="make_cef_event")
def _make_cef_event_factory() -> Callable[..., LogEvent]:
    """Factory fixture around :func:`make_cef_event`."""
    return make_cef_event


@pytest.fixture(name="make_leef_event")
def _make_leef_event_factory() -> Callable[..., LogEvent]:
    """Factory fixture around :func:`make_leef_event`."""
    return make_leef_event


@pytest.fixture(name="make_json_event")
def _make_json_event_factory() -> Callable[..., LogEvent]:
    """Factory fixture around :func:`make_json_event`."""
    return make_json_event


@pytest.fixture(name="make_evtx_event")
def _make_evtx_event_factory() -> Callable[..., LogEvent]:
    """Factory fixture around :func:`make_evtx_event`."""
    return make_evtx_event


@pytest.fixture(name="make_cloudtrail_event")
def _make_cloudtrail_event_factory() -> Callable[..., LogEvent]:
    """Factory fixture around :func:`make_cloudtrail_event`."""
    return make_cloudtrail_event


@pytest.fixture(name="make_nginx_event")
def _make_nginx_event_factory() -> Callable[..., LogEvent]:
    """Factory fixture around :func:`make_nginx_event`."""
    return make_nginx_event


@pytest.fixture(name="make_zeek_event")
def _make_zeek_event_factory() -> Callable[..., LogEvent]:
    """Factory fixture around :func:`make_zeek_event`."""
    return make_zeek_event


@pytest.fixture
def syslog_event() -> LogEvent:
    """Ready-made sshd failed-password syslog event."""
    return make_syslog_event()


@pytest.fixture
def cef_event() -> LogEvent:
    """Ready-made CEF firewall-deny event."""
    return make_cef_event()


@pytest.fixture
def leef_event() -> LogEvent:
    """Ready-made LEEF firewall-deny event."""
    return make_leef_event()


@pytest.fixture
def json_event() -> LogEvent:
    """Ready-made ECS-style JSON event."""
    return make_json_event()


@pytest.fixture
def evtx_event() -> LogEvent:
    """Ready-made EVTX 4625 failed-logon event."""
    return make_evtx_logon_failure()


@pytest.fixture
def evtx_process_creation_event() -> LogEvent:
    """Ready-made EVTX 4688 process-created event (``newprocessname`` key)."""
    return make_evtx_process_creation()


@pytest.fixture
def cloudtrail_event() -> LogEvent:
    """Ready-made CloudTrail ``ConsoleLogin`` failure (Root, failed auth)."""
    return make_cloudtrail_event(
        "ConsoleLogin",
        extensions={
            "error_code": "Failed authentication",
            "error_message": "Failed authentication",
            "user_type": "Root",
        },
    )


@pytest.fixture
def cloudtrail_stop_logging_event() -> LogEvent:
    """Ready-made Root ``StopLogging`` CloudTrail event."""
    return make_cloudtrail_stop_logging()


@pytest.fixture
def nginx_event() -> LogEvent:
    """Ready-made nginx ``POST 401`` access event."""
    return make_nginx_event()


@pytest.fixture
def zeek_event() -> LogEvent:
    """Ready-made Zeek ``conn`` event with ``S0`` state."""
    return make_zeek_event("conn")


@pytest.fixture
def all_format_events() -> dict[str, LogEvent]:
    """One representative synthetic event per supported format."""
    return {
        "evtx": make_evtx_logon_failure(),
        "syslog": make_syslog_event(),
        "cef": make_cef_event(),
        "leef": make_leef_event(),
        "json": make_json_event(),
        "aws_cloudtrail": make_cloudtrail_event(),
        "nginx": make_nginx_event(),
        "zeek": make_zeek_event("conn"),
    }


@pytest.fixture
def base_config() -> dict[str, Any]:
    """Canonical config dict (deep copy; every log source enabled, 0.6 bar)."""
    return _default_config()


@pytest.fixture
def make_config_file(tmp_path: Path) -> Callable[..., Path]:
    """Factory writing a ``config.yaml`` under ``tmp_path``.

    Pass a config mapping to override; defaults to the loader's defaults.
    """

    def _factory(
        config: Mapping[str, Any] | None = None,
        name: str = "config.yaml",
    ) -> Path:
        return _write_config_yaml(tmp_path / name, config or _default_config())

    return _factory


@pytest.fixture
def config_file(make_config_file: Callable[..., Path]) -> Path:
    """A ready ``config.yaml`` holding the canonical defaults."""
    return make_config_file()


@pytest.fixture
def make_mappings_csv(tmp_path: Path) -> Callable[..., Path]:
    """Factory writing a mapping CSV under ``tmp_path``.

    Accepts :class:`MappingRule` objects or raw cell dicts (see
    :func:`_write_mappings_csv`); returns the written file's path.
    """

    def _factory(
        rows: Sequence[MappingRule | Mapping[str, Any]],
        name: str = "attack_mappings.csv",
    ) -> Path:
        return _write_mappings_csv(tmp_path / name, rows)

    return _factory


@pytest.fixture
def sample_logs_dir() -> Path:
    """Directory holding the real copied sample logs."""
    if not SAMPLE_LOGS_DIR.is_dir():
        raise FileNotFoundError(f"sample logs directory missing: {SAMPLE_LOGS_DIR}")
    return SAMPLE_LOGS_DIR


@pytest.fixture
def sample_log_path(sample_logs_dir: Path) -> Callable[[str], Path]:
    """Factory mapping a format name to its real sample-log file."""

    def _factory(fmt: str) -> Path:
        return resolve_sample_log_path(fmt)

    return _factory
