"""Hand-curated hunt queries and generic fallback templates (Phase 5 Wave 2).

The hunt-query pipeline has three precedence tiers (Wave 1 dispatch,
``research/p5-wave1-full-results.md`` agent-420):

1. **hand-curated** — the M001-M020 core mapping set, synthesized into SPL
   from ``data/attack_mappings.csv`` patterns.  Highest trust, analyst-reviewed
   shape.  Emitted by :func:`curated_spl`.
2. **community-sourced** — a SigmaHQ rule converted via pySigma (the future
   conversion layer; this module only declares the attribution label).
3. **generic** — an ``# UNREVIEWED`` fallback template when neither curated nor
   SigmaHQ coverage exists.  Emitted by :func:`generic_template`.

This module owns tiers 1 and 3 plus the shared attribution vocabulary
(:data:`ATTRIBUTION_LABELS`).  Every public function returns a normalized
query dict (see :func:`curated_spl` for the keys) so the persistence layer
(:class:`database.models.TechniqueCoverage`) can store ``query_source`` +
``attribution_json`` and the work-list invariant (one query per missed
technique) holds.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Mapping

logger = logging.getLogger(__name__)

__all__ = (
    "ATTRIBUTION_LABELS",
    "CURATED_TECHNIQUES",
    "curated_spl",
    "generic_template",
)

# The three attribution labels (Wave 1 agent-420 / agent-427).  Every emitted
# query dict carries exactly one of these in ``attribution_label``.
ATTRIBUTION_LABELS: frozenset[str] = frozenset(
    {"hand-curated", "community-sourced", "generic"}
)

# Source-format -> Splunk sourcetype placeholder used by the generic template
# (and as a human-readable hint in curated queries).  Mirrors the sourcetype
# mapping in the Wave-1 generic-template design (agent-426).
_SOURCE_SOURCETYPE: dict[str, str] = {
    "evtx": "WinEventLog:Security",
    "syslog": "syslog",
    "cef": "cef",
    "leef": "leef",
    "json": "generic:json",
    "aws_cloudtrail": "aws:cloudtrail",
    "nginx": "nginx:access",
    "zeek": "zeek:*",
}

# Preference order when a curated technique has entries for several formats:
# evtx is the most-collected surface, then cloud, then network.
_FORMAT_PREFERENCE: tuple[str, ...] = ("evtx", "aws_cloudtrail", "zeek")


# ---------------------------------------------------------------------------
# Curated core set (M001-M020)
# ---------------------------------------------------------------------------

# Each entry is one hand-curated query synthesized from the mapping CSV row.
# Keys: technique_id, source_format, mapping_id, tactic, query.
# The query strings are faithful to the mapping's event_action / ext-key
# vocabulary and the Splunk Windows field names the splunk_windows_pipeline
# emits (EventCode, Image, CommandLine, ShareName, ...).  They are INERT:
# read-only stats/search pipes only.
_CURATED_ENTRIES: tuple[dict[str, Any], ...] = (
    {
        "technique_id": "T1110.001",
        "source_format": "evtx",
        "mapping_id": "M001",
        "tactic": "credential-access",
        "query": (
            'source="WinEventLog:Security" EventCode=4625'
            " | stats count by TargetUserName, IpAddress"
        ),
    },
    {
        "technique_id": "T1059.001",
        "source_format": "evtx",
        "mapping_id": "M002",
        "tactic": "execution",
        "query": (
            'source="WinEventLog:Security" EventCode=4688'
            ' Image IN ("*\\powershell.exe", "*\\pwsh.exe",'
            ' "*\\powershell_ise.exe")'
            " | stats count by ParentProcessName, Image"
        ),
    },
    {
        "technique_id": "T1059.003",
        "source_format": "evtx",
        "mapping_id": "M003",
        "tactic": "execution",
        "query": (
            'source="WinEventLog:Security" EventCode=4688'
            ' Image="*\\cmd.exe"'
            " | stats count by ParentProcessName, CommandLine"
        ),
    },
    {
        "technique_id": "T1053.005",
        "source_format": "evtx",
        "mapping_id": "M005",
        "tactic": "persistence",
        "query": (
            'source="WinEventLog:Security" EventCode=4688'
            ' CommandLine="*schtasks*" CommandLine="*/create*"'
            " | stats count by ParentProcessName, CommandLine"
        ),
    },
    {
        "technique_id": "T1543.003",
        "source_format": "evtx",
        "mapping_id": "M008",
        "tactic": "persistence",
        "query": (
            'source="WinEventLog:System" EventCode=7045'
            " | stats count by ServiceName, ImagePath"
        ),
    },
    {
        "technique_id": "T1136.001",
        "source_format": "evtx",
        "mapping_id": "M010",
        "tactic": "persistence",
        "query": (
            'source="WinEventLog:Security" EventCode=4720'
            " | stats count by TargetUserName"
        ),
    },
    {
        "technique_id": "T1078.003",
        "source_format": "evtx",
        "mapping_id": "M011",
        "tactic": "privilege-escalation",
        "query": (
            'source="WinEventLog:Security" EventCode=4732'
            " | stats count by TargetUserName, MemberName"
        ),
    },
    {
        "technique_id": "T1110.003",
        "source_format": "evtx",
        "mapping_id": "M012",
        "tactic": "credential-access",
        "query": (
            'source="WinEventLog:Security" EventCode=4771'
            " | stats count by TargetUserName, IpAddress"
        ),
    },
    {
        "technique_id": "T1021.002",
        "source_format": "evtx",
        "mapping_id": "M013",
        "tactic": "lateral-movement",
        "query": (
            'source="WinEventLog:Security" EventCode=5140'
            ' ShareName="*$*"'
            " | stats count by SourceAddress, ShareName"
        ),
    },
    {
        "technique_id": "T1685.005",
        "source_format": "evtx",
        "mapping_id": "M014",
        "tactic": "defense-evasion",
        "query": (
            'source="WinEventLog:Security" EventCode=1102'
            " | stats count by SubjectUserName"
        ),
    },
    {
        "technique_id": "T1110",
        "source_format": "aws_cloudtrail",
        "mapping_id": "M015",
        "tactic": "credential-access",
        "query": (
            'eventSource="signin.amazonaws.com" eventName="ConsoleLogin"'
            ' errorMessage="*Failed*"'
            " | stats count by userIdentity.arn"
        ),
    },
    {
        "technique_id": "T1685.002",
        "source_format": "aws_cloudtrail",
        "mapping_id": "M016",
        "tactic": "defense-evasion",
        "query": (
            'eventSource="cloudtrail.amazonaws.com"'
            ' eventName IN ("StopLogging", "DeleteTrail")'
            " | stats count by userIdentity.arn"
        ),
    },
    {
        "technique_id": "T1098.001",
        "source_format": "aws_cloudtrail",
        "mapping_id": "M017",
        "tactic": "persistence",
        "query": (
            'eventSource="iam.amazonaws.com" eventName="CreateAccessKey"'
            " | stats count by userIdentity.arn, requestParameters.userName"
        ),
    },
    {
        "technique_id": "T1098.003",
        "source_format": "aws_cloudtrail",
        "mapping_id": "M018",
        "tactic": "persistence",
        "query": (
            'eventSource="iam.amazonaws.com"'
            ' eventName IN ("AttachUserPolicy", "AttachRolePolicy")'
            " | stats count by userIdentity.arn"
        ),
    },
    {
        "technique_id": "T1110.001",
        "source_format": "zeek",
        "mapping_id": "M019",
        "tactic": "credential-access",
        "query": (
            'source="zeek:notice" note="SSH::Password_Guessing"'
            " | stats count by src, dst"
        ),
    },
)

# Index: technique_id -> list of curated entries (some techniques have more
# than one, e.g. T1110.001 via evtx M001 and zeek M019).
_CURATED_BY_TECHNIQUE: dict[str, list[dict[str, Any]]] = {}
for _entry in _CURATED_ENTRIES:
    _CURATED_BY_TECHNIQUE.setdefault(_entry["technique_id"], []).append(_entry)

# The set of technique ids covered by the curated core (M001-M020).
CURATED_TECHNIQUES: frozenset[str] = frozenset(_CURATED_BY_TECHNIQUE)


def _select_curated(
    entries: list[dict[str, Any]], closable_by: tuple[str, ...]
) -> dict[str, Any]:
    """Pick the best curated entry for a technique given ``closable_by``.

    Prefer an entry whose source format is *enabled* (not in closable_by),
    breaking ties by the format preference order :data:`_FORMAT_PREFERENCE`.
    If every entry's format is disabled (unusual), fall back to the first
    entry so the caller always gets a deterministic answer.

    Args:
        entries: Curated entries for one technique.
        closable_by: Alphabetically-sorted disabled source formats.

    Returns:
        The selected entry dict.
    """
    disabled = frozenset(closable_by)

    def _rank(entry: dict[str, Any]) -> tuple[int, int]:
        fmt = entry["source_format"]
        # Primary: enabled (0) sorts before disabled (1).
        enabled_rank = 0 if fmt not in disabled else 1
        # Secondary: format preference (lower = better); unknown formats last.
        pref = _FORMAT_PREFERENCE.index(fmt) if fmt in _FORMAT_PREFERENCE else 999
        return (enabled_rank, pref)

    return min(entries, key=_rank)


def curated_spl(
    technique_id: str,
    tactic: str,
    closable_by: tuple[str, ...],
) -> dict[str, Any] | None:
    """Return a hand-curated hunt query for a core-set technique, or ``None``.

    ``None`` means the technique is outside the M001-M020 core set and the
    caller should fall back to the SigmaHQ / generic tiers.

    Args:
        technique_id: Technique id in DB form (``T1059.001``).
        tactic: Canonical tactic slug (carried onto the output for trace).
        closable_by: Alphabetically-sorted disabled source formats; used to
            pick the best source format when the technique has several
            curated entries.

    Returns:
        A normalized query dict, or ``None``::

            {
                "query": <SPL string>,
                "query_language": "splunk",
                "attribution_label": "hand-curated",
                "source_rule_id": <mapping_id, e.g. "M001">,
                "source_format": <evtx|aws_cloudtrail|zeek>,
                "tactic": <tactic>,
                "attribution": {"author": "ATT&CK Coverage Mapper core set"},
            }
    """
    entries = _CURATED_BY_TECHNIQUE.get(technique_id)
    if entries is None:
        return None
    entry = _select_curated(entries, closable_by)
    return {
        "query": entry["query"],
        "query_language": "splunk",
        "attribution_label": "hand-curated",
        "source_rule_id": entry["mapping_id"],
        "source_format": entry["source_format"],
        "tactic": tactic,
        "attribution": {"author": "ATT&CK Coverage Mapper core set"},
    }


def generic_template(
    technique_id: str,
    tactic: str,
    closable_by: tuple[str, ...],
    source_format: str,
) -> dict[str, Any]:
    """Build an ``# UNREVIEWED`` generic fallback hunt query.

    This is the lowest-precedence tier (Wave 1 agent-426): used when a
    technique has no curated core entry and no matching SigmaHQ rule.  The
    template is source-aware (resolves the sourcetype for ``source_format``)
    and clearly marked ``UNREVIEWED`` so it is never executed uninspected.

    The ``{technique_clause}`` placeholder is the honest admission that no
    mapping exists -- the analyst must replace it with real field predicates
    before execution.

    Args:
        technique_id: Technique id in DB form (``T1059.001``).
        tactic: Canonical tactic slug.
        closable_by: Alphabetically-sorted disabled source formats (rendered
            into the header for traceability).
        source_format: The resolved target source format (from
            ``contributing_sources[0]`` or the most-generic enabled source).

    Returns:
        A normalized query dict::

            {
                "query": <SPL template string>,
                "query_language": "splunk",
                "attribution_label": "generic",
                "source_rule_id": None,
                "source_format": <source_format>,
                "tactic": <tactic>,
                "attribution": {},
            }
    """
    sourcetype = _SOURCE_SOURCETYPE.get(source_format, "unknown")
    closable = ",".join(closable_by) if closable_by else "none"
    query = (
        "# UNREVIEWED — inspect before use\n"
        f"# technique={technique_id} | tactic={tactic}\n"
        f"# closable_by={closable} | source={source_format}\n"
        f'source="{sourcetype}" {{technique_clause}}\n'
        "| stats count by host"
    )
    return {
        "query": query,
        "query_language": "splunk",
        "attribution_label": "generic",
        "source_rule_id": None,
        "source_format": source_format,
        "tactic": tactic,
        "attribution": {},
    }


def is_inert(query: str) -> bool:
    """Best-effort inertness guard for a generated query string.

    Queries must be read-only.  This uses a hybrid approach:
    1. A **blocklist** of explicitly destructive commands (defense in depth)
    2. An **allowlist** of permitted Splunk read-only commands

    The allowlist is applied to pipe-delimited commands only.  Keywords
    that are arguments (like ``by``, ``as``, ``over``) are not treated
    as commands.  Comment lines (starting with #) are skipped.

    Args:
        query: The full query string to check.

    Returns:
        False if a destructive pipe token is detected, True otherwise.
    """
    # Blocklist of explicitly destructive commands (always denied)
    _DESTRUCTIVE_COMMANDS = frozenset({
        "delete", "outputcsv", "outputtext", "collect", "sendalert",
        "sendemail", "run", "splunkjobs", "export", "outputlookup",
        "map", "inputcsv", "inputtext",
    })

    # Allowlist of permitted Splunk read-only commands/pipes
    _ALLOWED_COMMANDS = frozenset({
        "stats", "search", "where", "table", "eval", "rename",
        "fields", "head", "sort", "dedup", "regex", "transaction",
        "lookup", "join", "append", "convert", "bin", "timechart",
        "chart", "top", "rare", "statsdc", "eventstats", "streamstats",
        "addtotals", "addinfo", "like", "match", "case", "if",
        "coalesce", "nullif", "mvcombine", "mvexpand", "mvfilter",
        "mvindex", "mvjoin", "mvzip", "split", "upper", "lower",
        "substr", "replace", "strftime", "strptime", "tonumber",
        "tostring", "trim", "ltrim", "rtrim", "len", "exact",
        "ceil", "floor", "round", "abs", "random", "pi", "e",
        "null", "now", "relative_time", "time", "date", "datetime",
        "host", "source", "sourcetype", "index", "eventtype",
        "tag", "date_mday", "date_month", "date_year", "date_hour",
        "date_minute", "date_second", "date_wday", "date_quarter",
        "date_zone", "strcat", "urldecode", "xmlkv", "spath",
        "rex", "makemv", "mvexpand", "mvdedup", "mvfilter",
        "mvindex", "mvjoin", "mvzip", "foreach", "untable",
        "xyseries", "contingency", "associate", "correlate",
        "diff", "intersect", "pivot", "addtotals", "addinfo",
        "accum", "estcount", "eventcount",
    })

    # Check for destructive commands first (fast path)
    destructive = re.compile(
        r"\b(" + "|".join(re.escape(cmd) for cmd in _DESTRUCTIVE_COMMANDS) + r")\b",
        re.IGNORECASE,
    )
    if destructive.search(query):
        return False

    # Strip comment lines before splitting on pipe — comments may contain
    # pipe characters that would otherwise be misinterpreted as command
    # separators.
    lines = query.split("\n")
    code_lines = [line for line in lines if not line.strip().startswith("#")]
    code_only = "\n".join(code_lines)

    # Extract all pipe-delimited commands and verify each is allowed
    # Split on pipe character, take the first word of each segment
    pipe_segments = code_only.split("|")
    for i, segment in enumerate(pipe_segments):
        stripped = segment.strip()
        if not stripped:
            continue
        # Skip the first segment (search command with modifiers like index=main)
        if i == 0:
            continue
        # Get the command name (first word)
        parts = stripped.split(None, 1)
        if not parts:
            continue
        cmd = parts[0].lower().strip()
        # Skip empty commands
        if cmd and cmd not in _ALLOWED_COMMANDS:
            return False

    return True
