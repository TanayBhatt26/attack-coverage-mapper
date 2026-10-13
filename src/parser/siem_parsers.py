"""parser/siem_parsers.py — SIEM format parsers for ATT&CK Coverage Mapper.

Attribution / derivation notice:
    Adapted locally from github.com/TanayBhatt26/siem-log-parser authored by
    TanayBhatt26 (owner-authored upstream repository, provided without a
    license file). Adaptations made for this project:
      * imports retargeted from the upstream root-level ``schema`` module to
        ``parser.log_event_bridge.LogEvent`` (shared interface contract);
      * upstream ``sys.path.insert`` bootstrapping removed (library code
        resolves imports via PYTHONPATH=src instead);
      * the eight per-format parsers consolidated into this single module;
      * the upstream auto-detect router (which silently fell back to syslog)
        replaced by :func:`parse_log_content`, which raises ``ValueError`` on
        unknown formats instead;
      * ``normalize_severity`` carried over verbatim from the upstream
        ``schema.py`` because the bridge contract only pins the ``LogEvent``
        dataclass itself.

Parsing behavior is otherwise kept identical to the upstream implementation.
"""

import json
import logging
import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from parser.log_event_bridge import LogEvent

logger = logging.getLogger(__name__)

__all__ = [
    "parse_log_content",
    "parse_syslog",
    "parse_cef",
    "parse_leef",
    "parse_json",
    "parse_evtx",
    "parse_aws",
    "parse_nginx",
    "parse_zeek",
]

try:
    import defusedxml.ElementTree as SafeET
    from defusedxml.common import DefusedXmlException
except ImportError:
    SafeET = ET

    class DefusedXmlException(Exception):
        """Stand-in so the except clause below keeps working without defusedxml."""

    logger.warning("defusedxml not installed. Install it: pip install defusedxml")


# ---------------------------------------------------------------------------
# Shared severity normalization (adapted from upstream schema.py)
# ---------------------------------------------------------------------------

def normalize_severity(value) -> Tuple[str, int]:
    """Map a free-form severity value to ``(label, numeric_code)``.

    Unknown values default to ``("medium", 5)``. Behavior identical to the
    upstream ``schema.normalize_severity``.
    """
    mapping = {
        "0": ("low", 1), "1": ("low", 2), "2": ("low", 3),
        "3": ("medium", 4), "4": ("medium", 5), "5": ("medium", 6),
        "6": ("high", 7), "7": ("high", 8),
        "8": ("critical", 9), "9": ("critical", 10), "10": ("critical", 10),
        "low": ("low", 2), "medium": ("medium", 5),
        "high": ("high", 7), "critical": ("critical", 10),
        "info": ("low", 1), "warning": ("medium", 5),
        "error": ("high", 7), "alert": ("critical", 9),
        "emergency": ("critical", 10), "notice": ("low", 2), "debug": ("low", 1),
    }
    return mapping.get(str(value).lower().strip(), ("medium", 5))


# ---------------------------------------------------------------------------
# Input length bounds — defense against regex DoS on hostile log lines
# ---------------------------------------------------------------------------
MAX_LOG_LINE_LENGTH = 65536  # 64KB; reject/uncate lines longer than this


# ---------------------------------------------------------------------------
# Syslog (RFC 5424 & RFC 3164)
# ---------------------------------------------------------------------------

RFC5424 = re.compile(
    r"<(\d+)>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\[.*?\]|-)\s*(.*)"
)
RFC3164 = re.compile(
    r"<(\d+)>([A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?):\s*(.*)"
)
SEVERITY_LABELS = ["emergency","alert","critical","error","warning","notice","info","debug"]
FACILITY_LABELS = ["kern","user","mail","daemon","auth","syslog","lpr","news","uucp",
                   "cron","authpriv","ftp","local0","local1","local2","local3",
                   "local4","local5","local6","local7"]


def _decode_priority(pri):
    if pri < 0 or pri > 191:
        return "unknown", "unknown"
    fac = FACILITY_LABELS[pri >> 3] if (pri >> 3) < len(FACILITY_LABELS) else str(pri >> 3)
    sev = SEVERITY_LABELS[pri & 7] if (pri & 7) < len(SEVERITY_LABELS) else "unknown"
    return fac, sev


def parse_syslog(content: str) -> List[LogEvent]:
    """Parse RFC 5424 / RFC 3164 syslog text; unparsable lines become raw events."""
    events = []
    for line in content.splitlines():
        # Truncate hostile long lines to prevent regex DoS
        line = line.strip()[:MAX_LOG_LINE_LENGTH]
        if not line or line.startswith("#"):
            continue
        m = RFC5424.match(line)
        if m:
            pri, ver, ts, host, app, procid, msgid, sd, msg = m.groups()
            fac, sev = _decode_priority(int(pri))
            sev_label, sev_code = normalize_severity(sev)
            pid = None
            try: pid = int(procid) if procid != "-" else None
            except ValueError: pass
            events.append(LogEvent(
                timestamp=ts if ts != "-" else None, source_format="syslog",
                source_host=host if host != "-" else None,
                event_type=f"syslog/{fac}", event_action=app if app != "-" else None,
                severity=sev_label, severity_code=sev_code,
                process_name=app if app != "-" else None, process_id=pid,
                message=msg.strip(), raw=line,
                extensions={"facility": fac, "msgid": msgid, "structured_data": sd}
            ))
            continue
        m = RFC3164.match(line)
        if m:
            pri, ts_str, host, tag, msg = m.groups()
            fac, sev = _decode_priority(int(pri))
            sev_label, sev_code = normalize_severity(sev)
            try:
                # RFC 3164 omits the year. Heuristic: if parsed month is ahead of
                # the current month, assume the previous year (Dec logs read in Jan).
                now = datetime.now()
                year = now.year
                dt = datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")
                if dt.month > now.month or (dt.month == now.month and dt.day > now.day + 1):
                    dt = dt.replace(year=year - 1)
                ts = dt.isoformat()
            except ValueError:
                ts = ts_str
            events.append(LogEvent(
                timestamp=ts, source_format="syslog", source_host=host,
                event_type=f"syslog/{fac}", event_action=tag,
                severity=sev_label, severity_code=sev_code, process_name=tag,
                message=msg.strip(), raw=line, extensions={"facility": fac}
            ))
            continue
        events.append(LogEvent(source_format="syslog", message=line, raw=line))
    return events


# ---------------------------------------------------------------------------
# CEF (ArcSight Common Event Format)
# ---------------------------------------------------------------------------

CEF_HEADER = re.compile(
    r"CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(\d+)\|?(.*)?$",
    re.IGNORECASE
)

# suser (source actor) maps to username; duser intentionally stays in extensions
# so it cannot overwrite the source username.
CEF_FIELD_MAP = {
    "src": "source_ip", "spt": "source_port", "dst": "dest_ip", "dpt": "dest_port",
    "suser": "username", "sproc": "process_name", "spid": "process_id",
    "proto": "protocol", "in": "bytes_in", "out": "bytes_out",
    "act": "event_action", "cat": "category", "msg": "message",
    "rt": "timestamp", "start": "timestamp", "dvchost": "source_host",
}


def _parse_extensions(ext_str):
    """Parse CEF extension key=value pairs. Uses split instead of regex to avoid ReDoS."""
    result = {}
    parts = re.split(r'\s+(?=\w+=)', ext_str)
    for part in parts:
        if '=' in part:
            key, _, val = part.partition('=')
            result[key.strip()] = val.strip()
    return result


def parse_cef(content: str) -> List[LogEvent]:
    """Parse ArcSight CEF lines; unmapped extension keys land in ``extensions``."""
    events = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        raw = line
        cef_start = line.find("CEF:")
        if cef_start > 0:
            line = line[cef_start:]
        m = CEF_HEADER.match(line)
        if not m:
            events.append(LogEvent(source_format="cef", message=raw, raw=raw))
            continue
        ver, vendor, product, dev_ver, sig_id, name, severity_raw, ext_str = m.groups()
        sev_label, sev_code = normalize_severity(severity_raw.strip())
        extensions = _parse_extensions(ext_str or "")
        evt = LogEvent(source_format="cef", raw=raw, severity=sev_label, severity_code=sev_code)
        for cef_key, schema_key in CEF_FIELD_MAP.items():
            if cef_key in extensions:
                val = extensions.pop(cef_key)
                if schema_key in ("source_port", "dest_port", "bytes_in", "bytes_out"):
                    try: val = int(val)
                    except ValueError: pass
                setattr(evt, schema_key, val)
        evt.event_type = f"{vendor}/{product}"
        evt.event_action = evt.event_action or name
        if not evt.message:
            evt.message = f"{name} from {evt.source_ip or 'unknown'}"
        evt.extensions.update({"cef_version":ver,"vendor":vendor,"product":product,
                                "device_version":dev_ver,"signature_id":sig_id,"name":name,**extensions})
        events.append(evt)
    return events


# ---------------------------------------------------------------------------
# LEEF (IBM QRadar v1.0 & v2.0)
# ---------------------------------------------------------------------------

LEEF2_PREFIX = re.compile(r"LEEF:2\.0\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)", re.IGNORECASE | re.DOTALL)
LEEF1_HEADER = re.compile(r"LEEF:1\.0\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)", re.IGNORECASE | re.DOTALL)

LEEF_FIELD_MAP = {
    "src": "source_ip", "srcPort": "source_port",
    "dst": "dest_ip", "dstPort": "dest_port",
    "usrName": "username", "proto": "protocol",
    "cat": "category", "sev": "severity",
    "devTime": "timestamp", "devTimeFormat": None,
    "srcBytes": "bytes_in", "dstBytes": "bytes_out",
}


def _parse_attrs(attr_str, delimiter="\t"):
    result = {}
    pairs = attr_str.split(delimiter) if delimiter and delimiter in attr_str else re.split(r'\s+(?=\w+=)', attr_str)
    for pair in pairs:
        if "=" in pair:
            key, _, val = pair.partition("=")
            result[key.strip()] = val.strip()
    return result


def _resolve_delimiter(rest):
    if rest.startswith("^"):
        return "\t", rest[1:]
    m = re.match(r'^(0?x[0-9a-fA-F]{2})(.*)', rest, re.DOTALL)
    if m:
        try:
            hex_str = m.group(1)
            # Slice off the "0x" prefix explicitly (lstrip("0x") also eats '0'/'x' chars).
            if hex_str.lower().startswith("0x"):
                hex_str = hex_str[2:]
            delimiter = chr(int(hex_str, 16))
        except (ValueError, TypeError): delimiter = "\t"
        return delimiter, m.group(2)
    if rest and not rest[0].isalnum() and rest[0] not in ('"', "'"):
        return rest[0], rest[1:]
    return "\t", rest


def parse_leef(content: str) -> List[LogEvent]:
    """Parse IBM QRadar LEEF v1/v2 lines, resolving custom attribute delimiters."""
    events = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        raw = line
        m2 = LEEF2_PREFIX.match(line)
        m1 = LEEF1_HEADER.match(line)
        if m2:
            vendor, product, version, event_id, rest = m2.groups()
            delimiter, attrs_str = _resolve_delimiter(rest)
        elif m1:
            vendor, product, version, event_id, attrs_str = m1.groups()
            delimiter = "\t"
        else:
            events.append(LogEvent(source_format="leef", message=line, raw=raw))
            continue
        attrs = _parse_attrs(attrs_str, delimiter)
        sev_raw = attrs.get("sev", attrs.get("severity", "5"))
        sev_label, sev_code = normalize_severity(sev_raw)
        evt = LogEvent(source_format="leef", event_type=f"{vendor}/{product}",
                       event_action=event_id, severity=sev_label, severity_code=sev_code, raw=raw)
        for leef_key, schema_key in LEEF_FIELD_MAP.items():
            if leef_key in attrs and schema_key:
                val = attrs.pop(leef_key)
                if schema_key in ("source_port", "dest_port", "bytes_in", "bytes_out"):
                    try: val = int(val)
                    except ValueError: pass
                if schema_key == "severity":
                    val, sev_code2 = normalize_severity(val)
                    evt.severity_code = sev_code2
                setattr(evt, schema_key, val)
        if not evt.message:
            parts = [p for p in [evt.event_action, f"from {evt.source_ip}" if evt.source_ip else None,
                                  f"user {evt.username}" if evt.username else None] if p]
            evt.message = " | ".join(parts) if parts else f"LEEF event {vendor}/{product}"
        evt.extensions.update({"vendor":vendor,"product":product,"version":version,"event_id":event_id,**attrs})
        events.append(evt)
    return events


# ---------------------------------------------------------------------------
# Generic JSON / NDJSON (ECS, OCSF, raw)
# ---------------------------------------------------------------------------

ALIAS_MAP = {
    "timestamp":"timestamp","@timestamp":"timestamp","time":"timestamp","ts":"timestamp","event_time":"timestamp",
    "src_ip":"source_ip","sourceIPAddress":"source_ip","client_ip":"source_ip","source.ip":"source_ip",
    "host":"source_host","hostname":"source_host","source.host":"source_host",
    "src_port":"source_port","source.port":"source_port",
    "dst_ip":"dest_ip","destination.ip":"dest_ip","dst_port":"dest_port","destination.port":"dest_port",
    "user":"username","userName":"username","user.name":"username","actor.login":"username",
    "uid":"user_id","userId":"user_id","user.id":"user_id",
    "event_type":"event_type","event.type":"event_type","eventType":"event_type","type":"event_type",
    "action":"event_action","event.action":"event_action","eventName":"event_action",
    "severity":"severity","level":"severity","log.level":"severity","logLevel":"severity",
    "category":"category","event.category":"category",
    "process":"process_name","process.name":"process_name","processName":"process_name",
    "pid":"process_id","process.pid":"process_id",
    "protocol":"protocol","network.protocol":"protocol",
    "bytes_in":"bytes_in","source.bytes":"bytes_in","bytes_out":"bytes_out","destination.bytes":"bytes_out",
    "msg":"message","log":"message","message":"message","body":"message",
}
INT_FIELDS = {"source_port","dest_port","bytes_in","bytes_out","process_id"}


def _flatten(d, prefix="", sep="."):
    out = {}
    for k, v in d.items():
        full_key = f"{prefix}{sep}{k}" if prefix else k
        if isinstance(v, dict):
            out.update(_flatten(v, full_key, sep))
        else:
            out[full_key] = v
    return out


def _map_record(record):
    flat = _flatten(record)
    evt = LogEvent(source_format="json", raw=json.dumps(record, default=str))
    mapped_keys = set()
    for alias, schema_key in ALIAS_MAP.items():
        if alias in flat and alias not in mapped_keys:
            val = flat[alias]
            if val is None: continue
            mapped_keys.add(alias)
            if schema_key == "severity":
                sev_label, sev_code = normalize_severity(str(val))
                evt.severity = sev_label; evt.severity_code = sev_code
            else:
                if schema_key in INT_FIELDS:
                    try: val = int(val)
                    except (TypeError, ValueError): pass
                setattr(evt, schema_key, val)
    for k, v in record.items():
        if k not in mapped_keys:
            evt.extensions[k] = v
    return evt


def _extract_records(data):
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        for key in ("Records","events","logs","items","hits","data","results"):
            if key in data and isinstance(data[key], list):
                return [r for r in data[key] if isinstance(r, dict)]
        return [data]
    return []


def parse_json(content: str) -> List[LogEvent]:
    """Parse whole-file JSON or NDJSON; corrupt NDJSON lines become raw events."""
    events = []
    stripped = content.strip()

    # Try whole-file JSON parse first (handles JSON arrays and single objects)
    try:
        data = json.loads(stripped)
        for rec in _extract_records(data):
            events.append(_map_record(rec))
        return events
    except json.JSONDecodeError:
        pass

    # NDJSON — parse each line independently, skip bad ones
    lines = [l.strip() for l in content.splitlines() if l.strip()]
    for line in lines:
        try:
            item = json.loads(line)
            for rec in _extract_records(item):
                events.append(_map_record(rec))
        except json.JSONDecodeError:
            # Fallback — emit raw line as event for corrupt lines
            events.append(LogEvent(source_format="json", message=line, raw=line))

    return events


# ---------------------------------------------------------------------------
# Windows Event Log (EVTX, XML form)
# ---------------------------------------------------------------------------

EVENTID_MAP = {
    "4624": ("Authentication", "logon_success"),
    "4625": ("Authentication", "logon_failure"),
    "4634": ("Authentication", "logoff"),
    "4648": ("Authentication", "explicit_credential_logon"),
    "4672": ("Authentication", "special_privilege_logon"),
    "4688": ("Process",        "process_created"),
    "4689": ("Process",        "process_terminated"),
    "4698": ("Scheduled Task", "task_created"),
    "4702": ("Scheduled Task", "task_modified"),
    "4720": ("Account Management", "user_account_created"),
    "4726": ("Account Management", "user_account_deleted"),
    "4732": ("Account Management", "member_added_to_group"),
    "4740": ("Account Management", "account_locked_out"),
    "5140": ("Network",  "network_share_accessed"),
    "7036": ("Service",  "service_state_changed"),
    "7045": ("Service",  "new_service_installed"),
    "1102": ("Audit",    "audit_log_cleared"),
    "4663": ("File System", "object_access"),
    "4771": ("Authentication", "kerberos_pre_auth_failed"),
    "4776": ("Authentication", "ntlm_auth_attempt"),
}
SEVERITY_BY_LEVEL = {"1":"critical","2":"high","3":"medium","4":"low","5":"low"}


def _strip_ns(elem):
    for el in elem.iter():
        if "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    return elem


def _parse_event_xml(event_elem: ET.Element) -> LogEvent:
    evt = LogEvent(source_format="evtx")
    try: evt.raw = ET.tostring(event_elem, encoding="unicode")
    except Exception:
        logger.debug("EVTX raw serialization failed for one event", exc_info=True)
    event_elem = _strip_ns(event_elem)
    system = event_elem.find("System") or event_elem.find("s")
    if system is None:
        evt.message = evt.raw or "Unknown EVTX event"
        return evt
    event_id_el = system.find("EventID")
    event_id = (event_id_el.text or "").strip() if event_id_el is not None else ""
    level_el = system.find("Level")
    level = (level_el.text or "4").strip() if level_el is not None else "4"
    time_el = system.find("TimeCreated")
    if time_el is not None:
        evt.timestamp = time_el.get("SystemTime")
    computer_el = system.find("Computer")
    evt.source_host = (computer_el.text or "").strip() if computer_el is not None else None
    channel_el = system.find("Channel")
    channel = (channel_el.text or "").strip() if channel_el is not None else ""
    provider_el = system.find("Provider")
    provider_name = provider_el.get("Name") if provider_el is not None else None
    evt.severity = SEVERITY_BY_LEVEL.get(level, "low")
    evt.severity_code = normalize_severity(evt.severity)[1]
    if event_id in EVENTID_MAP:
        evt.event_type, evt.event_action = EVENTID_MAP[event_id]
    else:
        evt.event_type = channel or "Windows"
        evt.event_action = f"EventID-{event_id}"
    data_dict = {}
    event_data = event_elem.find("EventData")
    if event_data is not None:
        for data_el in event_data.findall("Data"):
            name = data_el.get("Name")
            text = (data_el.text or "").strip()
            if name:
                data_dict[name] = text
    evt.username = (data_dict.get("SubjectUserName") or data_dict.get("TargetUserName")
                    or data_dict.get("AccountName"))
    evt.source_ip = (data_dict.get("IpAddress") or data_dict.get("SourceAddress")
                     or data_dict.get("CallerIpAddress"))
    try:
        port_str = data_dict.get("IpPort") or data_dict.get("SourcePort")
        if port_str and port_str not in ("-","0",""):
            evt.source_port = int(port_str)
    except (ValueError, TypeError): pass
    evt.process_name = (data_dict.get("NewProcessName") or data_dict.get("ProcessName")
                        or data_dict.get("Application"))
    try:
        pid_str = data_dict.get("NewProcessId") or data_dict.get("ProcessId")
        if pid_str:
            evt.process_id = int(pid_str, 16) if str(pid_str).startswith("0x") else int(pid_str)
    except (ValueError, TypeError): pass
    evt.extensions.update({"event_id":event_id,"channel":channel,"provider":provider_name,"level":level,**data_dict})
    evt.message = (
        f"Windows Event {event_id}: {evt.event_action}"
        + (f" | user={evt.username}" if evt.username else "")
        + (f" | host={evt.source_host}" if evt.source_host else "")
        + (f" | src={evt.source_ip}" if evt.source_ip else "")
    )
    return evt


def _parse_evtx_file(filepath: str) -> List[LogEvent]:
    """Parse a binary .evtx file from a path using python-evtx (optional dep)."""
    try:
        import Evtx.Evtx as evtx
    except ImportError:
        return [LogEvent(source_format="evtx", severity="low",
                         message="python-evtx not installed. Run: pip install python-evtx", raw="")]
    events = []
    try:
        with evtx.Evtx(filepath) as log:
            for record in log.records():
                try:
                    root = SafeET.fromstring(record.xml())
                    events.append(_parse_event_xml(root))
                except Exception:
                    continue
    except Exception as e:
        events.append(LogEvent(source_format="evtx", message=f"Binary EVTX parse error: {e}", raw=""))
    return events


def parse_evtx(content) -> List[LogEvent]:
    """Parse Windows Event Logs from an XML string (or binary bytes)."""
    events = []
    # Binary .evtx — write to temp file, delegate to _parse_evtx_file
    if isinstance(content, bytes) and content[:8] == b"ElfFile\x00":
        import tempfile
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as tmp:
                tmp.write(content)
                tmp_path = tmp.name
            return _parse_evtx_file(tmp_path)
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)

    if isinstance(content, bytes):
        try: content = content.decode("utf-8")
        except UnicodeDecodeError: content = content.decode("latin-1")

    # XML string
    try:
        if "<Events>" not in content and (content.count("<Event ") + content.count("<Event>")) > 1:
            content = f"<Events>{content}</Events>"
        root = SafeET.fromstring(content)
        _strip_ns(root)
        if root.tag in ("Events",):
            elems = list(root)
        elif root.tag == "Event":
            elems = [root]
        else:
            elems = root.findall(".//Event")
        for elem in elems:
            events.append(_parse_event_xml(elem))
        return events
    except (ET.ParseError, DefusedXmlException):
        pass

    for line in content.splitlines():
        line = line.strip()
        if line:
            events.append(LogEvent(source_format="evtx", message=line, raw=line))
    return events


# ---------------------------------------------------------------------------
# AWS CloudTrail
# ---------------------------------------------------------------------------

# Map CloudTrail eventName prefixes → severity
SEVERITY_MAP = {
    "Delete": "high", "Remove": "high", "Terminate": "high",
    "Detach": "medium", "Disable": "high", "Deactivate": "high",
    "Create": "low", "Put": "low", "Update": "low", "Describe": "low",
    "List": "low", "Get": "low", "Failed": "critical",
    "Unauthorized": "critical", "Console": "medium",
}
# Specific high-value events
HIGH_VALUE = {
    "ConsoleLogin", "AssumeRole", "CreateUser", "DeleteUser",
    "AttachUserPolicy", "AttachRolePolicy", "CreateAccessKey",
    "DeleteAccessKey", "UpdateAccountPasswordPolicy", "StopLogging",
    "DeleteTrail", "PutBucketPolicy", "PutBucketAcl",
}


def _get_severity(event_name: str, error_code: str) -> Tuple[str, int]:
    if error_code and error_code not in ("-", ""):
        return normalize_severity("high")
    if event_name in HIGH_VALUE:
        return normalize_severity("high")
    for prefix, sev in SEVERITY_MAP.items():
        if event_name.startswith(prefix):
            return normalize_severity(sev)
    return normalize_severity("low")


def parse_aws(content: str) -> List[LogEvent]:
    """Parse AWS CloudTrail JSON records; eventName lands verbatim in event_action."""
    events = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return events

    records = []
    if isinstance(data, list):
        records = data
    elif isinstance(data, dict):
        records = data.get("Records", data.get("events", [data]))

    for rec in records:
        if not isinstance(rec, dict):
            continue

        event_name   = rec.get("eventName", "")
        event_time   = rec.get("eventTime", "")
        source_ip    = rec.get("sourceIPAddress", "")
        aws_region   = rec.get("awsRegion", "")
        event_source = rec.get("eventSource", "")
        error_code   = rec.get("errorCode", "")
        error_msg    = rec.get("errorMessage", "")
        event_type   = rec.get("eventType", "AwsApiCall")
        request_id   = rec.get("requestID", "")

        # User identity
        user_identity = rec.get("userIdentity", {})
        username = (user_identity.get("userName") or
                    user_identity.get("sessionContext", {}).get("sessionIssuer", {}).get("userName") or
                    user_identity.get("principalId", "").split(":")[-1] or
                    user_identity.get("type", ""))

        sev_label, sev_code = _get_severity(event_name, error_code)

        # Build message
        if error_code:
            message = f"AWS {event_name} FAILED ({error_code}): {error_msg or 'no details'}"
        else:
            message = f"AWS {event_name} by {username or 'unknown'} from {source_ip or 'unknown'}"

        evt = LogEvent(
            timestamp=event_time,
            source_format="aws_cloudtrail",
            source_ip=source_ip if not source_ip.endswith(".amazonaws.com") else None,
            event_type=f"AWS/{event_source.split('.')[0].upper() if event_source else 'CloudTrail'}",
            event_action=event_name,
            severity=sev_label,
            severity_code=sev_code,
            username=username or None,
            message=message,
            raw=json.dumps(rec, default=str),
            extensions={
                "aws_region": aws_region,
                "event_source": event_source,
                "event_type": event_type,
                "error_code": error_code,
                "error_message": error_msg,
                "request_id": request_id,
                "user_type": user_identity.get("type"),
                "account_id": user_identity.get("accountId"),
                "request_params": rec.get("requestParameters"),
            }
        )
        events.append(evt)

    return events


# ---------------------------------------------------------------------------
# Nginx / Apache access & error logs
# ---------------------------------------------------------------------------

# Combined Log Format: IP - USER [TIMESTAMP] "METHOD PATH PROTO" STATUS BYTES "REFERER" "UA"
COMBINED = re.compile(
    r'(\S+)\s+'              # client IP
    r'\S+\s+'                # ident (usually -)
    r'(\S+)\s+'              # auth user
    r'\[([^\]]+)\]\s+'       # timestamp
    r'"(\S+)\s+(\S+)\s+(\S+)"\s+'  # method, path, protocol
    r'(\d{3})\s+'            # status code
    r'(\S+)'                 # bytes
    r'(?:\s+"([^"]*)"\s+"([^"]*)")?'  # referer, user-agent (optional)
)

# Fallback pattern for malformed request lines ("-", "", "GET", "GET /path")
COMBINED_MALFORMED = re.compile(
    r'(\S+)\s+'              # client IP
    r'\S+\s+'                # ident
    r'(\S+)\s+'              # auth user
    r'\[([^\]]+)\]\s+'       # timestamp
    r'"([^"]*)"\s+'          # entire request line (any content)
    r'(\d{3})\s+'            # status code
    r'(\S+)'                 # bytes
    r'(?:\s+"([^"]*)"\s+"([^"]*)")?'  # referer, user-agent (optional)
)

# Error log: YYYY/MM/DD HH:MM:SS [LEVEL] PID#TID: *CID MESSAGE
NGINX_ERROR = re.compile(
    r'(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'\[(\w+)\]\s+'
    r'[\d#]+:\s+'
    r'(?:\*\d+\s+)?'
    r'(.*)'
)

STATUS_SEVERITY = {
    "1": ("low", 1), "2": ("low", 1), "3": ("low", 2),
    "401": ("medium", 5), "403": ("high", 7), "404": ("low", 2),
    "429": ("medium", 4), "499": ("medium", 4),
    "5": ("high", 7),
}


def _status_to_severity(code: str) -> Tuple[str, int]:
    if code in STATUS_SEVERITY:
        return STATUS_SEVERITY[code]
    prefix = code[0]
    return STATUS_SEVERITY.get(prefix, ("low", 2))


def _parse_nginx_ts(ts_str: str) -> str:
    """Convert '10/Oct/2024:13:55:36 +0530' to ISO-8601 keeping the timezone offset."""
    ts_str = ts_str.strip()
    try:
        # Full parse with timezone offset (e.g. "+0530", "-0700", "+0000")
        dt = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
        return dt.isoformat()
    except ValueError:
        pass
    try:
        # Fallback: no timezone present — treat as UTC
        dt = datetime.strptime(ts_str[:20], "%d/%b/%Y:%H:%M:%S")
        return dt.isoformat() + "Z"
    except ValueError:
        return ts_str


def parse_nginx(content: str) -> List[LogEvent]:
    """Parse combined/common access logs and nginx error logs."""
    events = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Try combined/common access log
        m = COMBINED.match(line)
        if m:
            ip, user, ts_raw, method, path, proto, status, size, referer, ua = m.groups()
            sev_label, sev_code = _status_to_severity(status)
            # Escalate for sensitive paths
            if any(p in path.lower() for p in ("/admin", "/wp-admin", "/.env", "/etc/passwd", "/shell", "/../")):
                sev_label, sev_code = "high", 7
            # Escalate for auth failures
            if status in ("401", "403"):
                sev_label, sev_code = normalize_severity("high")

            try:
                bytes_val = int(size) if size != "-" else None
            except ValueError:
                bytes_val = None

            evt = LogEvent(
                timestamp=_parse_nginx_ts(ts_raw),
                source_format="nginx",
                source_ip=ip if ip != "-" else None,
                event_type="HTTP/Access",
                event_action=f"{method} {status}",
                severity=sev_label,
                severity_code=sev_code,
                username=user if user != "-" else None,
                protocol=proto.split("/")[0] if "/" in proto else proto,
                bytes_out=bytes_val,
                message=f'{method} {path} → {status} from {ip}',
                raw=line,
                extensions={
                    "http_method": method,
                    "http_path": path,
                    "http_status": status,
                    "http_version": proto,
                    "referer": referer or "",
                    "user_agent": ua or "",
                    "response_bytes": size,
                }
            )
            events.append(evt)
            continue

        # Try malformed request line pattern
        m = COMBINED_MALFORMED.match(line)
        if m:
            ip, user, ts_raw, request_line, status, size, referer, ua = m.groups()
            # Parse what we can from the request line
            req_parts = request_line.split() if request_line else []
            method = req_parts[0] if len(req_parts) >= 1 else "-"
            path = req_parts[1] if len(req_parts) >= 2 else "-"
            proto = req_parts[2] if len(req_parts) >= 3 else "-"

            sev_label, sev_code = _status_to_severity(status)
            if status in ("401", "403"):
                sev_label, sev_code = normalize_severity("high")

            try:
                bytes_val = int(size) if size != "-" else None
            except ValueError:
                bytes_val = None

            evt = LogEvent(
                timestamp=_parse_nginx_ts(ts_raw),
                source_format="nginx",
                source_ip=ip if ip != "-" else None,
                event_type="HTTP/Access",
                event_action=f"{method} {status}",
                severity=sev_label,
                severity_code=sev_code,
                username=user if user != "-" else None,
                bytes_out=bytes_val,
                message=f'{method} {path} → {status} from {ip}',
                raw=line,
                extensions={
                    "http_method": method,
                    "http_path": path,
                    "http_status": status,
                    "request_line": request_line,
                    "referer": referer or "",
                    "user_agent": ua or "",
                    "response_bytes": size,
                }
            )
            events.append(evt)
            continue

        # Try nginx error log
        m = NGINX_ERROR.match(line)
        if m:
            ts, level, msg = m.groups()
            sev_label, sev_code = normalize_severity(level.lower())
            try:
                dt = datetime.strptime(ts, "%Y/%m/%d %H:%M:%S")
                iso_ts = dt.isoformat() + "Z"
            except ValueError:
                iso_ts = ts
            events.append(LogEvent(
                timestamp=iso_ts,
                source_format="nginx",
                event_type="HTTP/Error",
                event_action="error",
                severity=sev_label,
                severity_code=sev_code,
                message=msg.strip(),
                raw=line,
                extensions={"log_level": level}
            ))
            continue

        # Fallback
        events.append(LogEvent(source_format="nginx", message=line, raw=line))

    return events


# ---------------------------------------------------------------------------
# Zeek (formerly Bro) TSV logs: conn, http, dns, notice, weird
# ---------------------------------------------------------------------------

# conn_state codes → severity
CONN_STATE_SEV = {
    "S0":  ("medium", 5),   # Connection attempt, no reply
    "REJ": ("high", 7),     # Connection rejected
    "RSTO":("medium", 4),   # Originator aborted
    "RSTR":("medium", 4),   # Responder aborted
    "SF":  ("low", 1),      # Normal established+closed
    "S1":  ("low", 2),      # Established, not closed
    "S2":  ("low", 2),      "S3":("low",2),
    "OTH": ("low", 2),
}

# Notice/weird actions
NOTICE_SEV = {
    "Scan::Port_Scan":         ("high", 8),
    "Scan::Address_Scan":      ("high", 8),
    "SSH::Password_Guessing":  ("critical", 9),
    "SSH::Bruteforcing":       ("critical", 10),
    "Heartbleed::SSL_Heartbeat_Attack": ("critical", 10),
    "DNS::External_Name":      ("medium", 4),
}


def _parse_value(val: str) -> Optional[str]:
    """Return None for empty/unset Zeek field values."""
    return None if val in ("-", "(empty)", "") else val


def _try_int(val: str) -> Optional[int]:
    try: return int(val)
    except (ValueError, TypeError): return None


def _try_float(val: str) -> Optional[float]:
    try: return float(val)
    except (ValueError, TypeError): return None


def _zeek_ts(h: Dict[str, Any]) -> Optional[str]:
    ts_float = _try_float(h.get("ts", ""))
    return datetime.fromtimestamp(ts_float, tz=timezone.utc).isoformat() if ts_float else None


def _parse_conn(fields: List[str], headers: List[str]) -> LogEvent:
    h = {k: _parse_value(v) for k, v in zip(headers, fields)}
    conn_state = h.get("conn_state", "")
    sev_label, sev_code = CONN_STATE_SEV.get(conn_state, ("low", 2))

    return LogEvent(
        timestamp=_zeek_ts(h),
        source_format="zeek",
        source_ip=h.get("id.orig_h"),
        source_port=_try_int(h.get("id.orig_p")),
        dest_ip=h.get("id.resp_h"),
        dest_port=_try_int(h.get("id.resp_p")),
        protocol=h.get("proto"),
        event_type="Network/Connection",
        event_action=conn_state or "connection",
        severity=sev_label,
        severity_code=sev_code,
        bytes_in=_try_int(h.get("orig_bytes")),
        bytes_out=_try_int(h.get("resp_bytes")),
        message=(f"Zeek conn {conn_state}: {h.get('id.orig_h','?')}:{h.get('id.orig_p','?')} → "
                 f"{h.get('id.resp_h','?')}:{h.get('id.resp_p','?')} ({h.get('proto','?')})"),
        extensions={k: v for k, v in h.items() if v and k not in
                    ("ts","id.orig_h","id.orig_p","id.resp_h","id.resp_p","proto","orig_bytes","resp_bytes")}
    )


def _parse_http(fields: List[str], headers: List[str]) -> LogEvent:
    h = {k: _parse_value(v) for k, v in zip(headers, fields)}
    status = h.get("status_code", "")
    sev_label = "high" if status and status.startswith(("4","5")) else "low"
    if status in ("401","403"): sev_label = "high"
    sev_label, sev_code = normalize_severity(sev_label)

    method = h.get("method","")
    uri = h.get("uri","")
    host = h.get("host","")
    return LogEvent(
        timestamp=_zeek_ts(h),
        source_format="zeek",
        source_ip=h.get("id.orig_h"),
        source_port=_try_int(h.get("id.orig_p")),
        dest_ip=h.get("id.resp_h"),
        dest_port=_try_int(h.get("id.resp_p")),
        event_type="Network/HTTP",
        event_action=f"{method} {status}".strip(),
        severity=sev_label,
        severity_code=sev_code,
        username=h.get("username"),
        message=f"HTTP {method} {host}{uri} → {status}",
        extensions={k: v for k, v in h.items() if v}
    )


def _parse_dns(fields: List[str], headers: List[str]) -> LogEvent:
    h = {k: _parse_value(v) for k, v in zip(headers, fields)}
    query = h.get("query","")
    qtype = h.get("qtype_name","")
    # Flag suspicious DNS (long TXT labels for exfil, known-bad TLDs, etc.)
    sev_label = "low"
    if qtype == "TXT" and len(query) > 30:
        sev_label = "medium"  # potential DNS exfil
    if any(x in query for x in (".onion", ".bit", "dyndns", ".ru", ".cn")):
        sev_label = "medium"
    sev_label, sev_code = normalize_severity(sev_label)

    return LogEvent(
        timestamp=_zeek_ts(h),
        source_format="zeek",
        source_ip=h.get("id.orig_h"),
        dest_ip=h.get("id.resp_h"),
        event_type="Network/DNS",
        event_action=f"DNS {qtype} query",
        severity=sev_label,
        severity_code=sev_code,
        message=f"DNS {qtype} query: {query}",
        extensions={k: v for k, v in h.items() if v}
    )


def _parse_notice(fields: List[str], headers: List[str]) -> LogEvent:
    h = {k: _parse_value(v) for k, v in zip(headers, fields)}
    note = h.get("note","")
    sev_label, sev_code = NOTICE_SEV.get(note, normalize_severity("medium"))

    return LogEvent(
        timestamp=_zeek_ts(h),
        source_format="zeek",
        source_ip=h.get("src") or h.get("id.orig_h"),
        dest_ip=h.get("dst") or h.get("id.resp_h"),
        event_type="Network/Notice",
        event_action=note,
        severity=sev_label,
        severity_code=sev_code,
        message=h.get("msg","") or f"Zeek notice: {note}",
        extensions={k: v for k, v in h.items() if v}
    )


LOG_PARSERS = {
    "conn":    _parse_conn,
    "http":    _parse_http,
    "dns":     _parse_dns,
    "notice":  _parse_notice,
    "weird":   _parse_notice,  # similar structure
}


def parse_zeek(content: str) -> List[LogEvent]:
    """Parse Zeek TSV logs (#path/#fields headers select the per-type handler)."""
    events = []
    headers = []
    log_type = "conn"

    for line in content.splitlines():
        line = line.rstrip()
        if not line:
            continue
        if line.startswith("#"):
            if line.startswith("#path"):
                log_type = line.split("\t", 1)[-1].strip()
            elif line.startswith("#fields"):
                headers = line.split("\t")[1:]
            continue

        if not headers:
            continue

        fields = line.split("\t")
        if len(fields) != len(headers):
            logger.debug("Zeek field count mismatch: expected %d fields, got %d (log_type=%s)",
                         len(headers), len(fields), log_type)
        parse_fn = LOG_PARSERS.get(log_type, _parse_conn)
        try:
            evt = parse_fn(fields, headers)
            evt.raw = line
            events.append(evt)
        except Exception:
            events.append(LogEvent(source_format="zeek", message=line, raw=line))

    return events


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

_PARSERS = {
    "syslog": parse_syslog,
    "cef": parse_cef,
    "leef": parse_leef,
    "json": parse_json,
    "evtx": parse_evtx,
    "aws_cloudtrail": parse_aws,
    "nginx": parse_nginx,
    "zeek": parse_zeek,
}

SUPPORTED_FORMATS = frozenset(_PARSERS)


def parse_log_content(content: str, fmt: str) -> List[LogEvent]:
    """Parse raw log ``content`` of the given ``fmt`` into normalized LogEvents.

    ``fmt`` must be one of: syslog, cef, leef, json, evtx, aws_cloudtrail,
    nginx, zeek (case-insensitive, surrounding whitespace ignored). Unlike the
    upstream router there is NO silent fallback: an unknown format raises
    ``ValueError``.

    Returns a list with one LogEvent per parsed record/line; unparsable lines
    are preserved as raw-message events by the individual parsers.
    """
    fmt_normalized = (fmt or "").strip().lower()
    parser = _PARSERS.get(fmt_normalized)
    if parser is None:
        raise ValueError(
            f"Unknown log format {fmt!r}; expected one of: {', '.join(sorted(_PARSERS))}"
        )
    return parser(content)
