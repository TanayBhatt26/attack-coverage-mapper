"""Golden parser-level trace tests for the bundled real sample logs.

Each expectation below was hand-derived by tracing the corresponding line of
data/sample_logs/* through the adapted parsers (ported from
github.com/TanayBhatt26/siem-log-parser, authored by TanayBhatt26;
owner-authored upstream without license file, adapted locally). Behavior is
asserted exactly as the upstream parsers produce it, including quirks such as:

* EVTX keeps the raw Windows SystemTime string and puts EventData names back
  verbatim into extensions alongside event_id/channel/provider/level.
* Syslog facilities above the label table (pri >> 3 >= 20) degrade to their
  numeric string (the iptables sample line with pri 165 becomes facility "20").
* Nginx sensitive-path hits (/etc/passwd, /.env) escalate severity to high even
  on 404 responses.
* Zeek conn.log rows carry the raw conn_state code as event_action and convert
  epoch floats to tz-aware ISO-8601 strings.
"""

import logging
import uuid
from pathlib import Path

import pytest

from parser.log_event_bridge import LogEvent
from parser.siem_parsers import parse_log_content

logger = logging.getLogger(__name__)

SAMPLE_DIR = Path(__file__).resolve().parents[1] / "data" / "sample_logs"

pytestmark = pytest.mark.integration


def _parse(name: str, fmt: str) -> list:
    """Read a bundled sample file and parse it through the adapter."""
    content = (SAMPLE_DIR / name).read_text(encoding="utf-8")
    return parse_log_content(content, fmt)


@pytest.fixture(scope="module")
def evtx_events() -> list:
    return _parse("sample.evtx.xml", "evtx")


@pytest.fixture(scope="module")
def aws_events() -> list:
    return _parse("sample.aws.json", "aws_cloudtrail")


@pytest.fixture(scope="module")
def json_events() -> list:
    return _parse("sample.json", "json")


@pytest.fixture(scope="module")
def syslog_events() -> list:
    return _parse("sample.syslog", "syslog")


@pytest.fixture(scope="module")
def cef_events() -> list:
    return _parse("sample.cef", "cef")


@pytest.fixture(scope="module")
def leef_events() -> list:
    return _parse("sample.leef", "leef")


@pytest.fixture(scope="module")
def nginx_events() -> list:
    return _parse("sample.nginx.log", "nginx")


@pytest.fixture(scope="module")
def zeek_events() -> list:
    return _parse("sample.zeek.log", "zeek")


class TestParserDispatch:
    """Contract checks shared by every format before per-format goldens."""

    def test_unknown_format_raises_value_error(self) -> None:
        """parse_log_content must reject formats outside the known enum."""
        for bogus in ("bogus", "windows_eventlog", "", "AWS"):
            with pytest.raises(ValueError):
                parse_log_content("anything", bogus)

    def test_events_are_logevents_with_unique_uuid_ids(self, nginx_events: list) -> None:
        """Every returned object is a LogEvent carrying unique uuid4 ids."""
        assert all(isinstance(evt, LogEvent) for evt in nginx_events)
        ids = [evt.event_id for evt in nginx_events]
        assert len(set(ids)) == len(ids)
        for evt_id in ids:
            uuid.UUID(evt_id)  # raises ValueError if not a valid UUID string


class TestEvtxTrace:
    """Golden trace for data/sample_logs/sample.evtx.xml (4 Windows events)."""

    def test_count_and_format(self, evtx_events: list) -> None:
        assert len(evtx_events) == 4
        assert {e.source_format for e in evtx_events} == {"evtx"}

    def test_failed_logon_4625(self, evtx_events: list) -> None:
        evt = evtx_events[0]
        assert evt.event_type == "Authentication"
        assert evt.event_action == "logon_failure"
        assert evt.timestamp == "2024-11-15T12:00:00.000000000Z"
        assert evt.source_host == "WIN-SERVER01"
        assert evt.username == "administrator"
        assert evt.source_ip == "192.168.1.200"
        assert evt.source_port == 54321
        assert evt.severity == "medium"  # Level 3
        assert evt.severity_code == 5
        assert evt.category is None  # EVTX never populates category
        assert evt.message == (
            "Windows Event 4625: logon_failure | user=administrator"
            " | host=WIN-SERVER01 | src=192.168.1.200"
        )
        assert set(evt.extensions) == {
            "event_id", "channel", "provider", "level",
            "TargetUserName", "IpAddress", "IpPort",
        }
        assert evt.extensions["event_id"] == "4625"
        assert evt.extensions["channel"] == "Security"
        assert evt.extensions["provider"] == "Microsoft-Windows-Security-Auditing"
        assert evt.extensions["level"] == "3"
        assert evt.raw.startswith("<Event")

    def test_process_creation_4688(self, evtx_events: list) -> None:
        evt = evtx_events[1]
        assert evt.event_type == "Process"
        assert evt.event_action == "process_created"
        assert evt.timestamp == "2024-11-15T12:01:00.000000000Z"
        assert evt.username == "jdoe"  # SubjectUserName fallback chain
        assert evt.process_name == r"C:\Windows\System32\cmd.exe"
        assert evt.process_id == int("0x1234", 16)  # hex pid decoded
        assert evt.severity == "low"  # Level 4
        assert evt.severity_code == 2
        assert evt.source_ip is None
        assert evt.category is None
        assert evt.extensions["NewProcessName"] == r"C:\Windows\System32\cmd.exe"

    def test_logon_success_4624(self, evtx_events: list) -> None:
        evt = evtx_events[2]
        assert evt.event_action == "logon_success"
        assert evt.username == "svcAccount"  # TargetUserName
        assert evt.source_ip == "10.10.5.50"
        assert evt.source_port == 49876
        assert evt.severity == "low"
        assert evt.severity_code == 2
        assert evt.message == (
            "Windows Event 4624: logon_success | user=svcAccount"
            " | host=WIN-DC01 | src=10.10.5.50"
        )

    def test_new_service_installed_7045(self, evtx_events: list) -> None:
        evt = evtx_events[3]
        assert evt.event_type == "Service"
        assert evt.event_action == "new_service_installed"
        assert evt.severity == "high"  # Level 2
        assert evt.severity_code == 7
        assert evt.username == "LocalSystem"  # AccountName fallback
        # ImagePath is NOT promoted to process_name by upstream behavior.
        assert evt.process_name is None
        assert evt.source_ip is None and evt.source_port is None
        assert evt.extensions["channel"] == "System"
        assert evt.extensions["provider"] == "Service Control Manager"
        assert evt.extensions["ServiceName"] == "MaliciousService"
        assert evt.extensions["ImagePath"] == r"C:\Temp\evil.exe"


class TestCloudTrailTrace:
    """Golden trace for data/sample_logs/sample.aws.json (4 CloudTrail records)."""

    def test_count_and_format(self, aws_events: list) -> None:
        assert len(aws_events) == 4
        assert {e.source_format for e in aws_events} == {"aws_cloudtrail"}

    def test_extensions_always_carry_canonical_keys(self, aws_events: list) -> None:
        expected = {
            "aws_region", "event_source", "event_type", "error_code",
            "error_message", "request_id", "user_type", "account_id",
            "request_params",
        }
        for evt in aws_events:
            assert set(evt.extensions) == expected
            assert evt.extensions["request_params"] is None
            assert evt.category is None

    def test_failed_console_login(self, aws_events: list) -> None:
        evt = aws_events[0]
        assert evt.event_action == "ConsoleLogin"  # eventName verbatim
        assert evt.timestamp == "2024-11-15T12:00:00Z"
        assert evt.source_ip == "203.0.113.42"
        assert evt.event_type == "AWS/SIGNIN"  # eventSource first label upper
        assert evt.username == "jdoe"
        assert evt.severity == "high"  # errorCode present forces high
        assert evt.severity_code == 7
        assert evt.extensions["error_code"] == "Failed authentication"
        assert evt.extensions["error_message"] == "Failed authentication"
        assert evt.extensions["event_type"] == "AwsConsoleSignIn"
        assert evt.extensions["aws_region"] == "us-east-1"
        assert evt.extensions["request_id"] == "req-001"
        assert evt.extensions["user_type"] == "IAMUser"
        assert evt.extensions["account_id"] == "123456789012"
        assert evt.message == "AWS ConsoleLogin FAILED (Failed authentication): Failed authentication"

    def test_create_access_key_is_high_value(self, aws_events: list) -> None:
        evt = aws_events[1]
        assert evt.event_action == "CreateAccessKey"
        assert evt.event_type == "AWS/IAM"
        assert evt.username == "admin"
        assert evt.severity == "high"  # HIGH_VALUE membership
        assert evt.severity_code == 7
        assert evt.extensions["error_code"] == ""  # absent errorCode -> ""
        assert evt.extensions["user_type"] == "IAMUser"
        assert evt.message == "AWS CreateAccessKey by admin from 198.51.100.10"

    def test_delete_bucket_severity_by_prefix(self, aws_events: list) -> None:
        evt = aws_events[2]
        assert evt.event_action == "DeleteBucket"
        assert evt.event_type == "AWS/S3"
        assert evt.extensions["aws_region"] == "us-west-2"
        assert evt.severity == "high"  # "Delete" prefix
        assert evt.severity_code == 7
        assert evt.source_ip == "10.0.0.50"

    def test_root_stop_logging(self, aws_events: list) -> None:
        evt = aws_events[3]
        assert evt.event_action == "StopLogging"
        assert evt.event_type == "AWS/CLOUDTRAIL"
        assert evt.username == "Root"  # falls back to userIdentity.type
        assert evt.extensions["user_type"] == "Root"
        assert evt.severity == "high"  # HIGH_VALUE membership
        assert evt.severity_code == 7
        assert evt.source_ip == "203.0.113.99"


class TestEcsJsonTrace:
    """Golden trace for data/sample_logs/sample.json (3 ECS NDJSON lines)."""

    def test_count_and_format(self, json_events: list) -> None:
        assert len(json_events) == 3
        assert {e.source_format for e in json_events} == {"json"}

    def test_blocked_connection_event(self, json_events: list) -> None:
        evt = json_events[0]
        assert evt.timestamp == "2024-11-15T12:00:00.000Z"
        assert evt.source_ip == "192.168.1.100"
        assert evt.source_port == 54321
        assert evt.dest_ip == "10.0.0.1"
        assert evt.dest_port == 443
        assert evt.event_type == "connection"  # event.type alias
        assert evt.event_action == "deny"  # event.action alias
        assert evt.category == "network"  # event.category alias
        assert evt.username == "jdoe"
        assert evt.process_name == "nginx"
        assert evt.process_id == 1234
        assert evt.severity == "medium"  # log.level warning
        assert evt.severity_code == 5
        assert evt.message == "Unauthorized access attempt blocked"
        # extensions keep unmapped TOP-LEVEL groups whole (nested dicts not exploded).
        assert len(evt.extensions) == 6
        assert evt.extensions["event"] == {"type": "connection", "action": "deny",
                                           "category": "network"}
        # @timestamp was consumed by the alias map, so it is NOT in extensions.
        assert "@timestamp" not in evt.extensions

    def test_ssh_brute_force_event(self, json_events: list) -> None:
        evt = json_events[1]
        assert evt.event_type == "Authentication"
        assert evt.event_action == "logon_failure"
        assert evt.category == "authentication"
        assert evt.username == "root"
        assert evt.source_ip == "10.10.10.5" and evt.source_port == 22
        assert evt.dest_ip == "192.168.1.50" and evt.dest_port == 22
        assert evt.severity == "high"  # log.level error
        assert evt.severity_code == 7
        assert evt.message == "SSH brute force detected: 50 failed attempts"

    def test_process_spawned_by_office(self, json_events: list) -> None:
        evt = json_events[2]
        assert evt.source_ip == "172.16.0.20"
        assert evt.source_port is None  # source.port absent stays default
        assert evt.dest_ip is None and evt.dest_port is None
        assert evt.event_action == "process_created"
        assert evt.username == "SYSTEM"
        assert evt.process_name == "cmd.exe"
        assert evt.process_id == 4567
        assert evt.severity == "critical"  # log.level critical
        assert evt.severity_code == 10
        assert evt.message == "Suspicious process spawned by Office application"
        assert len(evt.extensions) == 5  # event/log/process/source/user groups


class TestSyslogTrace:
    """Golden trace for data/sample_logs/sample.syslog (4 RFC 5424 lines)."""

    def test_count_and_format(self, syslog_events: list) -> None:
        assert len(syslog_events) == 4
        assert {e.source_format for e in syslog_events} == {"syslog"}
        for evt in syslog_events:
            assert evt.event_action == evt.process_name  # APP-NAME free-form

    def test_nginx_line_pri34_auth_critical(self, syslog_events: list) -> None:
        evt = syslog_events[0]
        assert evt.timestamp == "2024-11-15T12:00:00.000Z"
        assert evt.source_host == "web-server-01"
        assert evt.event_type == "syslog/auth"  # pri 34 -> facility 4
        assert evt.event_action == "nginx"
        assert evt.process_name == "nginx"
        assert evt.process_id == 1234
        assert evt.severity == "critical"  # pri & 7 == 2
        assert evt.severity_code == 10
        assert evt.message == "192.168.1.100 - GET /admin HTTP/1.1 403"
        assert evt.extensions == {"facility": "auth", "msgid": "-",
                                  "structured_data": "-"}

    def test_iptables_line_facility_degrades_to_number(self, syslog_events: list) -> None:
        """pri 165 -> facility index 20 is past the label table -> literal "20"."""
        evt = syslog_events[1]
        assert evt.event_type == "syslog/20"
        assert evt.extensions["facility"] == "20"
        assert evt.severity == "low"  # pri & 7 == 5 -> notice
        assert evt.severity_code == 2
        assert evt.source_host == "firewall-01"
        assert evt.process_name == "iptables"
        assert evt.process_id == 5678
        assert evt.extensions["msgid"] == "ID47"
        assert evt.message == "Failed password for root from 10.0.0.5 port 22"

    def test_mysqld_line_pri13_user_notice(self, syslog_events: list) -> None:
        evt = syslog_events[2]
        assert evt.event_type == "syslog/user"
        assert evt.event_action == "mysqld"
        assert evt.severity == "low"
        assert evt.severity_code == 2
        assert evt.process_id == 9012
        assert evt.message == "Access denied for user root@192.168.5.20"

    def test_sshd_line_pri86_authpriv_info(self, syslog_events: list) -> None:
        evt = syslog_events[3]
        assert evt.event_type == "syslog/authpriv"  # pri 86 -> facility 10
        assert evt.event_action == "sshd"
        assert evt.severity == "low"  # pri & 7 == 6 -> info
        assert evt.severity_code == 1
        assert evt.process_id == 4321
        assert evt.message == "Accepted publickey for deploy from 10.10.1.5 port 54322"


class TestCefTrace:
    """Golden trace for data/sample_logs/sample.cef (4 CEF lines)."""

    def test_count_and_format(self, cef_events: list) -> None:
        assert len(cef_events) == 4
        assert {e.source_format for e in cef_events} == {"cef"}

    def test_pan_os_url_filtering_block(self, cef_events: list) -> None:
        evt = cef_events[0]
        assert evt.event_type == "Palo Alto Networks/PAN-OS"
        assert evt.event_action == "block"  # act beats header name
        assert evt.timestamp == "Nov 15 2024 12:00:00"  # rt kept as-is
        assert evt.source_ip == "192.168.1.100"
        assert evt.source_port == 54321
        assert evt.dest_ip == "93.184.216.34"
        assert evt.dest_port == 443
        assert evt.protocol == "TCP"
        assert evt.category == "malware"
        assert evt.username == "jdoe"
        assert evt.severity == "high"  # CEF severity 7
        assert evt.severity_code == 8
        assert evt.message == "Blocked connection to known malicious URL"
        assert set(evt.extensions) == {
            "cef_version", "vendor", "product", "device_version",
            "signature_id", "name",
        }
        assert evt.extensions["signature_id"] == "threat/url"
        assert evt.extensions["cef_version"] == "0"

    def test_asa_allow_without_category(self, cef_events: list) -> None:
        evt = cef_events[1]
        assert evt.event_action == "allow"
        assert evt.category is None  # no cat= extension
        assert evt.protocol == "UDP"
        assert evt.dest_port == 53
        assert evt.severity == "medium"  # CEF severity 3
        assert evt.severity_code == 4
        assert evt.username == "system"
        # No msg= -> synthesized message from name + source ip.
        assert evt.message == "Built outbound TCP connection from 10.0.0.5"

    def test_fortigate_phishing_blocked(self, cef_events: list) -> None:
        evt = cef_events[2]
        assert evt.event_type == "Fortinet/FortiGate"
        assert evt.event_action == "blocked"
        assert evt.category == "phishing"
        assert evt.username == "attacker"
        assert evt.severity == "critical"  # CEF severity 8
        assert evt.severity_code == 9
        assert evt.message == "Phishing site blocked"

    def test_defender_quarantine_no_network_fields(self, cef_events: list) -> None:
        evt = cef_events[3]
        assert evt.event_type == "Microsoft/Defender"
        assert evt.event_action == "quarantine"
        assert evt.category == "trojan"
        assert evt.username == r"DOMAIN\jsmith"
        assert evt.severity == "critical"  # CEF severity 9
        assert evt.severity_code == 10
        assert evt.dest_ip is None
        assert evt.source_port is None and evt.dest_port is None
        assert evt.protocol is None
        assert evt.message == "Trojan:Win32/Trickbot detected"


class TestLeefTrace:
    """Golden trace for data/sample_logs/sample.leef (v2 tab + v1 space lines)."""

    def test_count_and_format(self, leef_events: list) -> None:
        assert len(leef_events) == 2
        assert {e.source_format for e in leef_events} == {"leef"}

    def test_leef2_qradar_authfail(self, leef_events: list) -> None:
        evt = leef_events[0]
        assert evt.event_type == "IBM/QRadar"
        assert evt.event_action == "AuthFail"  # LEEF event id field
        assert evt.timestamp == "Nov 15 2024 12:00:00"  # devTime honored
        assert evt.source_ip == "10.0.0.5"
        assert evt.source_port == 22
        assert evt.dest_ip == "192.168.1.10"
        assert evt.dest_port == 22
        assert evt.protocol == "TCP"
        assert evt.category == "Authentication"
        assert evt.username == "root"
        assert evt.severity == "critical"  # sev=8
        assert evt.severity_code == 9
        assert evt.message == "AuthFail | from 10.0.0.5 | user root"
        # ^ delimiter handled; devTime/devTimeFormat stay out of mapped fields,
        # devTimeFormat has no schema mapping so it survives into extensions.
        assert set(evt.extensions) == {
            "vendor", "product", "version", "event_id", "devTimeFormat",
        }

    def test_leef1_symantec_no_devtime(self, leef_events: list) -> None:
        evt = leef_events[1]
        assert evt.event_type == "Symantec/SEP"
        assert evt.event_action == "5001"
        assert evt.timestamp is None  # no devTime attribute
        assert evt.source_ip == "192.168.5.50"
        assert evt.source_port == 4444
        assert evt.dest_ip == "10.10.10.1"
        assert evt.dest_port == 80
        assert evt.protocol == "TCP"
        assert evt.category == "Intrusion"
        assert evt.username == r"DOMAIN\jdoe"
        assert evt.severity == "high"  # sev=7
        assert evt.severity_code == 8
        assert evt.message == r"5001 | from 192.168.5.50 | user DOMAIN\jdoe"
        assert set(evt.extensions) == {
            "vendor", "product", "version", "event_id",
        }


class TestNginxTrace:
    """Golden trace for data/sample_logs/sample.nginx.log (6 combined-format lines)."""

    def test_count_and_common_fields(self, nginx_events: list) -> None:
        assert len(nginx_events) == 6
        for evt in nginx_events:
            assert evt.source_format == "nginx"
            assert evt.event_type == "HTTP/Access"
            assert evt.protocol == "HTTP"  # proto stripped of version
            assert set(evt.extensions) == {
                "http_method", "http_path", "http_status", "http_version",
                "referer", "user_agent", "response_bytes",
            }

    def test_actions_and_users_in_file_order(self, nginx_events: list) -> None:
        actions = ["GET 200", "POST 403", "GET 200", "GET 404", "GET 404",
                   "DELETE 200"]
        users = [None, "admin", None, None, None, "jdoe"]
        bytes_out = [2326, 512, 4096, 256, 162, 128]
        for evt, action, user, size in zip(nginx_events, actions, users, bytes_out):
            assert evt.event_action == action  # "<METHOD> <status>"
            assert evt.username == user
            assert evt.bytes_out == size

    def test_timestamps_keep_source_offsets(self, nginx_events: list) -> None:
        offsets = ["+00:00", "+05:30", "+00:00", "+00:00", "+00:00", "+00:00"]
        for evt, offset in zip(nginx_events, offsets):
            assert evt.timestamp.endswith(offset)
        assert nginx_events[0].timestamp == "2024-11-15T12:00:00+00:00"
        assert nginx_events[1].timestamp == "2024-11-15T12:00:15+05:30"

    def test_plain_200_is_low(self, nginx_events: list) -> None:
        evt = nginx_events[0]
        assert evt.severity == "low"
        assert evt.severity_code == 1
        assert evt.source_ip == "203.0.113.42"
        assert evt.message == "GET /index.html \u2192 200 from 203.0.113.42"
        assert evt.extensions["user_agent"] == "Mozilla/5.0"
        assert evt.extensions["referer"] == "-"

    def test_wp_admin_403_is_high(self, nginx_events: list) -> None:
        evt = nginx_events[1]
        assert evt.severity == "high"
        assert evt.severity_code == 7
        assert evt.extensions["http_path"] == "/wp-admin/login.php"
        assert evt.extensions["referer"] == "https://example.com"

    def test_sensitive_paths_escalate_even_on_404(self, nginx_events: list) -> None:
        for idx in (3, 4):  # /etc/passwd and /.env probes
            evt = nginx_events[idx]
            assert evt.severity == "high"  # path escalation overrides 404 low
            assert evt.severity_code == 7
        assert nginx_events[3].extensions["http_path"] == "/etc/passwd"
        assert nginx_events[3].extensions["user_agent"] == "Nikto/2.1.6"
        assert nginx_events[3].message == "GET /etc/passwd \u2192 404 from 203.0.113.55"
        assert nginx_events[4].extensions["http_path"] == "/.env"


class TestZeekTrace:
    """Golden trace for data/sample_logs/sample.zeek.log (conn.log, 4 rows)."""

    def test_count_and_conn_semantics(self, zeek_events: list) -> None:
        assert len(zeek_events) == 4
        states = ["SF", "REJ", "S0", "SF"]  # action = raw conn_state code
        severities = [("low", 1), ("high", 7), ("medium", 5), ("low", 1)]
        for evt, state, (label, code) in zip(zeek_events, states, severities):
            assert evt.source_format == "zeek"
            assert evt.event_type == "Network/Connection"
            assert evt.event_action == state
            assert evt.severity == label
            assert evt.severity_code == code

    def test_established_ssl_connection_row(self, zeek_events: list) -> None:
        evt = zeek_events[0]
        assert evt.timestamp == "2024-11-15T12:00:00+00:00"  # epoch float -> UTC ISO
        assert evt.source_ip == "203.0.113.42"
        assert evt.source_port == 54321
        assert evt.dest_ip == "10.0.0.1"
        assert evt.dest_port == 443
        assert evt.protocol == "tcp"
        assert evt.bytes_in == 1024
        assert evt.bytes_out == 8192
        assert evt.message == "Zeek conn SF: 203.0.113.42:54321 \u2192 10.0.0.1:443 (tcp)"
        # Mapped columns excluded; unset sentinel values would be dropped.
        assert evt.extensions == {
            "uid": "Cabc1", "service": "ssl", "duration": "1.234",
            "conn_state": "SF", "missed_bytes": "0", "history": "ShADadFf",
        }

    def test_rejected_ssh_connection_row(self, zeek_events: list) -> None:
        evt = zeek_events[1]
        assert evt.timestamp == "2024-11-15T12:01:00+00:00"
        assert evt.source_ip == "198.51.100.10"
        assert evt.source_port == 22001
        assert evt.dest_ip == "192.168.1.10"
        assert evt.dest_port == 22
        assert evt.bytes_in == 0 and evt.bytes_out == 0  # explicit zeros kept
        assert evt.extensions["service"] == "ssh"
        assert evt.extensions["history"] == "S"

    def test_half_open_http_scan_row(self, zeek_events: list) -> None:
        evt = zeek_events[2]
        assert evt.timestamp == "2024-11-15T12:02:00+00:00"
        assert evt.event_action == "S0"
        assert evt.bytes_in == 512000
        assert evt.bytes_out == 128
        assert evt.extensions["duration"] == "60.123"

    def test_dns_udp_row(self, zeek_events: list) -> None:
        evt = zeek_events[3]
        assert evt.timestamp == "2024-11-15T12:03:00+00:00"
        assert evt.protocol == "udp"
        assert evt.dest_ip == "8.8.8.8"
        assert evt.dest_port == 53
        assert evt.extensions["service"] == "dns"
        assert evt.extensions["history"] == "Dd"
