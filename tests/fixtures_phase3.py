"""Phase-3 fixtures -- mini coverage dataset + golden-snapshot builders.

Wave 2 (Coverage Engine + Gap Clustering) test support. Everything here is
plain hashable data plus small builder functions, so the module imports
without importing any Phase-3 engine module (those are built in parallel;
tests inject the engine's frozen dataclass *classes* where needed).

The mini dataset is designed so that every Wave-1 contract edge case is
exercised deterministically and every expected value can be recomputed by
hand from the contracts:

- (A) hashability: :func:`ensure_contract_a` recursively verifies that a
  returned object tree only contains ``None|bool|int|float|str|tuple|
  frozenset|frozen-dataclass`` with tuples at every collection depth.
- (B) platform scope: techniques with canonical and odd-cased platform
  values probe element-wise case-insensitive membership; macOS/IaaS
  techniques probe exclusion.
- (C) populate idempotency: rules cover insert/update/delete/stale paths,
  revoked skips (incl. the real M016->T1562.008 situation), the
  deprecated-treated-as-revoked path (contract G1) and orphan techniques.
  Confidence semantics follow contract D: per (technique, datasource)
  ``max(base * tier_mult)`` with the tier derived *statically* from rule
  shape -- ``match_type == 'heuristic'`` -> 0.40, else non-empty
  ``ext_keys`` -> 1.0, else action-only -> 0.85 -- capped at 0.95.
  (This resolves the raw-base vs tier-adjusted divergence flagged in
  research/p3-wave1-full-results.md; see GOLDEN_PAIR_ROWS_REAL.)
- (D) coverage: per-tactic goldens include multi-tactic double counting,
  zero-filled tactics, and inclusive-threshold boundaries.
- (E) gaps: honest ``closable_by`` positives (T1190 -> nginx) and
  negatives (T1136.001 -> () despite a cef mapping, because the static
  projection is below threshold).
- (F) clustering: policy-shape inputs (n=0, n<=3, separated >=4) plus the
  real-world single-cluster fallback expectation (best silhouette
  ~= 0.168 < 0.20).
- (G/H) loader/config: a mini STIX bundle with ``stealth`` /
  ``defense-impairment`` phases, an unknown phase, deprecated and revoked
  flags; clustering config defaults and invalid-value samples.

Floating-point note: golden confidences are written as *expressions*
(``base * TIER_ACTION`` etc.), never as decimal literals, so they are
bit-identical to engine arithmetic under IEEE-754 regardless of repr.

Offline and dependency-free beyond the stdlib; no pytest import so the
module doubles as a standalone self-check via ``python -m`` style runs.
"""

from __future__ import annotations

import csv
import dataclasses
import logging
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

logger = logging.getLogger(__name__)

__all__ = [
    "ALIAS_PHASE_MAP",
    "CANONICAL_TACTICS",
    "CONFIG_CLUSTERING_DEFAULTS",
    "CONFIG_INVALID_CLUSTERING_CASES",
    "CONF_CAP",
    "DEPRECATED_AS_REVOKED_NOTE",
    "EXPECTED_ALIAS_TACTICS",
    "EXPECTED_UNKNOWN_PHASE_COUNT",
    "GAP_SORT_NOTE",
    "MINI_CONFIG",
    "MINI_DATASOURCES",
    "MINI_RULES",
    "MINI_STIX_BUNDLE",
    "MINI_TECHNIQUES",
    "MINI_TACTIC_TOTALS",
    "MINI_PAIR_ROWS",
    "MINI_POPULATE_FIRST_RUN",
    "MINI_POPULATE_IDEMPOTENT_RERUN",
    "MINI_POPULATE_DISABLE_ZEEK",
    "MINI_POPULATE_ENABLE_NGINX",
    "MINI_GAPS",
    "MINI_DETECTABLE_IDS",
    "CLUSTER_POLICY_CASES",
    "CLUSTER_LABEL_SPEC",
    "CLUSTER_SUMMARY_SPEC",
    "REAL_EXECUTION",
    "REAL_REVOKED_SKIP_IDS",
    "REAL_DEPRECATED_PERSISTENCE_IDS",
    "REAL_CLOSABLE_EXAMPLES",
    "REAL_CLUSTER_FALLBACK",
    "REAL_UNIVERSE_COUNTS",
    "REAL_GAP_COUNT_RANGE",
    "SCENARIO_ZERO_ENABLED",
    "SCENARIO_EMPTY_DB",
    "TIER_EXT",
    "TIER_ACTION",
    "TIER_HEURISTIC",
    "THRESHOLD",
    "assert_mini_dataset_consistent",
    "build_frozen",
    "build_mini_tactic_coverage",
    "build_mini_coverage_gaps",
    "ensure_contract_a",
    "make_stix_attack_pattern",
    "write_mini_config_yaml",
    "write_mini_mappings_csv",
]


# ---------------------------------------------------------------------------
# Contract D constants
# ---------------------------------------------------------------------------

#: Static tier multiplier for extension-evidence rules (non-empty ext_keys).
TIER_EXT = 1.0
#: Static tier multiplier for action-only rules.
TIER_ACTION = 0.85
#: Static tier multiplier for heuristic rules (match_type == "heuristic").
TIER_HEURISTIC = 0.40
#: Hard ceiling for any detection confidence score.
CONF_CAP = 0.95
#: Default detectability threshold (config.yaml detection_confidence_threshold);
#: comparison is inclusive (>=).
THRESHOLD = 0.6

#: Canonical ATT&CK Enterprise tactic emission order (contract D).
CANONICAL_TACTICS: tuple[str, ...] = (
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
)

#: v19 bundle renamed TA0005: these kill-chain phases must alias to
#: ``defense-evasion`` BEFORE the ENTERPRISE_TACTICS allowlist (contract G2).
#: Unknown phases stay out of tactics but increment LoadReport's
#: ``unknown_phase_count`` warning counter.
ALIAS_PHASE_MAP: Mapping[str, str] = {
    "stealth": "defense-evasion",
    "defense-impairment": "defense-evasion",
}

#: Docstring-grade note for the deprecated flag handling (contract G1):
#: ``x_mitre_deprecated=true`` is honored exactly like ``revoked=true``
#: (same skip path, same report bucket); 12 deprecated attack-patterns
#: exist in the v19 bundle, 4 of them tagged persistence.
DEPRECATED_AS_REVOKED_NOTE = (
    "x_mitre_deprecated=true is treated as revoked=true (same flag column, "
    "same skip path); 12 bundle attack-patterns are deprecated, 4 of them "
    "persistence-tagged."
)

#: Gap ordering is tactic-major (canonical order), then best_confidence
#: ascending, then attack_id ascending as the deterministic tie-break.
GAP_SORT_NOTE = "(tactic canonical asc, best_confidence asc, attack_id asc)"


# ---------------------------------------------------------------------------
# Mini dataset -- datasources
# ---------------------------------------------------------------------------

# (id, name, log_format, enabled) -- mirrors DataSourceType columns. Formats
# and enable/disable flags mirror the real config.yaml (cef/leef/nginx off).
MINI_DATASOURCES: tuple[tuple[int, str, str, bool], ...] = (
    (1, "windows-eventlog", "evtx", True),
    (2, "linux-syslog", "syslog", True),
    (3, "cloud-trail", "aws_cloudtrail", True),
    (7, "generic-json", "json", True),
    (4, "web-access", "nginx", False),
    (5, "cef-device", "cef", False),
    (6, "zeek-sensor", "zeek", True),
)

#: Datasource ids by log format for quick lookups in tests.
_DS_ID = {fmt: ds_id for ds_id, _name, fmt, _en in MINI_DATASOURCES}


# ---------------------------------------------------------------------------
# Mini dataset -- techniques
# ---------------------------------------------------------------------------
# (stix_id, attack_id, name, tactics, platforms, revoked, deprecated)
# ``deprecated`` models the x_mitre_deprecated flag (contract G1); platforms
# keep canonical ATT&CK casing except T1021.001 which probes the
# case-insensitive scope match (contract B).

_STIX = "attack-pattern--00000000-0000-4000-8000-{:012d}"

MINI_TECHNIQUES: tuple[tuple[str, str, str, tuple[str, ...], tuple[str, ...], bool, bool], ...] = (
    # -- in scope (platforms contain "windows" case-insensitively), alive --
    (_STIX.format(1), "T1059.001", "PowerShell",
     ("execution",), ("Windows",), False, False),
    (_STIX.format(2), "T1059.003", "Windows Command Shell",
     ("execution",), ("Windows",), False, False),
    (_STIX.format(3), "T1047", "Windows Management Instrumentation",
     ("execution",), ("Windows",), False, False),
    (_STIX.format(4), "T1569.002", "System Services: Service Execution",
     ("execution",), ("Windows",), False, False),
    (_STIX.format(5), "T1059.009", "Cloud API",
     ("execution",), ("Windows",), False, False),
    (_STIX.format(6), "T1110.001", "Brute Force: Password Guessing",
     ("credential-access",), ("Windows",), False, False),
    (_STIX.format(7), "T1078", "Valid Accounts",
     ("defense-evasion", "privilege-escalation"), ("Windows",), False, False),
    (_STIX.format(8), "T1190", "Exploit Public-Facing Application",
     ("initial-access",), ("Windows", "Linux"), False, False),
    (_STIX.format(9), "T1136.001", "Create Account: Local Account",
     ("persistence",), ("Windows",), False, False),
    (_STIX.format(10), "T1098", "Account Manipulation",
     ("persistence", "credential-access"), ("Windows", "SaaS"), False, False),
    (_STIX.format(11), "T1021.001", "Remote Desktop Protocol",
     ("lateral-movement",), ("WINDOWS",), False, False),  # odd casing on purpose
    (_STIX.format(12), "T1036", "Masquerading",
     ("defense-evasion",), ("Windows",), False, False),  # post-alias tactic
    # -- alive but out of scope under platform_scope "windows" --
    (_STIX.format(13), "T1555", "Credentials from Password Stores",
     ("credential-access",), ("macOS",), False, False),
    # -- excluded from every denominator: revoked / deprecated (G1) --
    (_STIX.format(14), "T1070.001", "Clear Windows Event Logs",
     ("defense-evasion",), ("Windows",), True, False),
    (_STIX.format(15), "T1562.008", "Disable Cloud Logs",
     ("defense-evasion",), ("IaaS",), True, False),
    (_STIX.format(16), "T1108", "Access Removal",
     ("persistence",), ("Windows",), False, True),  # deprecated only
)

_ATTACK_ID_TO_STIX = {row[1]: row[0] for row in MINI_TECHNIQUES}


# ---------------------------------------------------------------------------
# Mini dataset -- mapping rules (14-column CSV shape)
# ---------------------------------------------------------------------------
# Row layout matches data/attack_mappings.csv / MappingRule exactly:
# (mapping_id, source_format, event_action_pattern, ext_keys, ext_value_pattern,
#  match_type, is_core, technique_id, tactic, base_confidence,
#  visibility_hint, evidence_ref, sigma_rule_id, notes)
#
# Static tiers implied by shape (contract D):
#   ext_keys non-empty            -> TIER_EXT      (unless heuristic)
#   ext_keys empty, action set    -> TIER_ACTION
#   match_type == "heuristic"     -> TIER_HEURISTIC
# Only VALID_SOURCE_FORMATS formats appear here (load_mappings rejects
# anything else); a direct-construction unknown-format probe lives in
# tests, not in the CSV.

MINI_RULES: tuple[tuple[str, str, str, str, str, str, bool, str, str, float, int, str, str, str], ...] = (
    # T1059.001: ext rule wins (0.75) over action-only rule (0.68) on evtx.
    ("X01", "evtx", "^process_created$", "newprocessname",
     "(?i)\\\\powershell\\.exe\"?$", "regex", True,
     "T1059.001", "execution", 0.75, 3, "ref", "", "ps spawn"),
    ("X02", "evtx", "^process_created$", "",
     "", "regex", True,
     "T1059.001", "execution", 0.80, 3, "ref", "", "generic proc create"),
    # T1059.003: plain ext rule.
    ("X03", "evtx", "^process_created$", "newprocessname",
     "(?i)\\\\cmd\\.exe\"?$", "regex", True,
     "T1059.003", "execution", 0.70, 3, "ref", "", "cmd spawn"),
    # T1047: action-only rule -> 0.90 * 0.85.
    ("X04", "evtx", "^process_created$", "",
     "", "regex", True,
     "T1047", "execution", 0.90, 3, "ref", "", "wmic"),
    # T1569.002: ext rule with base 1.0 exercises the 0.95 cap.
    ("X05", "evtx", "^new_service_installed$", "servicename",
     "", "exists", True,
     "T1569.002", "execution", 1.0, 3, "ref", "", "svc install"),
    # T1110.001: action-only evtx 0.51 (below), heuristic json 0.18 (below),
    # action-only zeek 0.765 (above) -- three-datasource spread.
    ("X06", "evtx", "^logon_failure$", "",
     "", "regex", True,
     "T1110.001", "credential-access", 0.60, 3, "ref", "", "4625 guess"),
    ("X07", "json", "^authentication_failure$", "source_ip",
     "", "heuristic", False,
     "T1110.001", "credential-access", 0.45, 2, "ref", "", "json weak signal"),
    ("X08", "zeek", "^ssh_password_guessing$", "",
     "", "regex", True,
     "T1110.001", "credential-access", 0.90, 3, "ref", "", "zeek notice"),
    # T1078: two evtx rules on one datasource, ext 0.55 beats action 0.4675.
    ("X09", "evtx", "^special_privilege_logon$", "",
     "", "regex", True,
     "T1078", "defense-evasion", 0.55, 3, "ref", "", "priv logon"),
    ("X10", "evtx", "^logon_success$", "targetusername",
     "", "exists", True,
     "T1078", "privilege-escalation", 0.55, 3, "ref", "", "valid acct logon"),
    # T1190: nginx only (disabled) -> gap, closable_by=("nginx",).
    ("X11", "nginx", "^request_received$", "url",
     "(?i)(wp-login|/etc/passwd)", "regex", True,
     "T1190", "initial-access", 0.75, 3, "ref", "", "web exploit probe"),
    # T1136.001: cef only (disabled) and projected 0.25 -> honest-filter
    # negative: closable_by must be () despite the mapping existing.
    ("X12", "cef", "^device_event$", "fname",
     "", "regex", True,
     "T1136.001", "persistence", 0.25, 2, "ref", "", "weak cef signal"),
    # T1098: syslog action-only 0.3825 -> sub-threshold pair row.
    ("X13", "syslog", "^auth_failure$", "",
     "", "regex", True,
     "T1098", "persistence", 0.45, 2, "ref", "", "unix auth fail"),
    # T1059.009: heuristic on an ENABLED source -> 0.20 pair row, still gap.
    ("X19", "syslog", "^cloud_api_call$", "useragent",
     "", "heuristic", False,
     "T1059.009", "execution", 0.50, 2, "ref", "", "cloud api weak"),
    # Skipped-path rules: revoked (x2), deprecated (x1), orphan techniques (x2).
    ("X16", "evtx", "^audit_log_cleared$", "",
     "", "regex", True,
     "T1070.001", "defense-evasion", 0.95, 3, "ref", "", "revoked target"),
    ("X18", "aws_cloudtrail", "^stop_logging$", "eventname",
     "", "exists", True,
     "T1562.008", "defense-evasion", 0.90, 3, "ref", "",
     "real-world M016 analogue: revoked until retarget to T1685.002"),
    ("X17", "evtx", "^file_deleted$", "",
     "", "regex", True,
     "T1108", "persistence", 0.80, 3, "ref", "", "deprecated target"),
    ("X14", "evtx", "^orphan_event$", "",
     "", "regex", True,
     "T9998", "credential-access", 0.90, 3, "ref", "", "unresolvable"),
    ("X15", "json", "^orphan_object$", "",
     "", "regex", True,
     "T9999", "collection", 0.70, 3, "ref", "", "unresolvable"),
)


def _static_conf(*rules: tuple[tuple[str, ...], str, float]) -> float:
    """Return ``min(max(base*tier), CAP)`` over ``(ext_keys, mtype, base)``."""
    best = 0.0
    for ext_keys, match_type, base in rules:
        if match_type == "heuristic":
            mult = TIER_HEURISTIC
        elif ext_keys:
            mult = TIER_EXT
        else:
            mult = TIER_ACTION
        best = max(best, min(base * mult, CONF_CAP))
    return best


# ---------------------------------------------------------------------------
# Golden expectations -- populate (contract C)
# ---------------------------------------------------------------------------
# Field name -> value for the PopulateReport frozen DC (contract C). Rows are
# (technique_stix_id, technique_attack_id, datasource_id, confidence,
#  is_detectable) for the technique_coverage table after populate.

_MINI_RULES_BY = {(r[0]): r for r in MINI_RULES}


def _pair(attack_id: str, fmt: str, *rule_ids: str) -> tuple[str, str, int, float, bool]:
    """Build one expected coverage row from its winning rules."""
    shaped = [
        (tuple(_MINI_RULES_BY[rid][3].split()), _MINI_RULES_BY[rid][5],
         float(_MINI_RULES_BY[rid][9]))
        for rid in rule_ids
    ]
    conf = _static_conf(*shaped)
    return (
        _ATTACK_ID_TO_STIX[attack_id],
        attack_id,
        _DS_ID[fmt],
        conf,
        conf >= THRESHOLD,
    )


#: Expected technique_coverage rows after the first populate run, sorted by
#: (datasource_id, attack_id). 10 rows: 6 evtx, 2 syslog, 1 json, 1 zeek;
#: nothing for disabled nginx/cef or for skipped revoked/deprecated/orphans.
MINI_PAIR_ROWS: tuple[tuple[str, str, int, float, bool], ...] = tuple(sorted(
    (
        _pair("T1047", "evtx", "X04"),
        _pair("T1059.001", "evtx", "X01", "X02"),
        _pair("T1059.003", "evtx", "X03"),
        _pair("T1059.009", "syslog", "X19"),
        _pair("T1078", "evtx", "X09", "X10"),
        _pair("T1098", "syslog", "X13"),
        _pair("T1110.001", "evtx", "X06"),
        _pair("T1110.001", "json", "X07"),
        _pair("T1110.001", "zeek", "X08"),
        _pair("T1569.002", "evtx", "X05"),
    ),
    key=lambda row: (row[2], row[1]),
))

#: PopulateReport kwargs after the FIRST run on an empty table.
MINI_POPULATE_FIRST_RUN: Mapping[str, Any] = {
    "rows_upserted": len(MINI_PAIR_ROWS),
    "rows_inserted": len(MINI_PAIR_ROWS),
    "rows_updated": 0,
    "rows_deleted": 0,
    # Sorted ascending for determinism (contract C leaves order free; the
    # fixtures pin sorted order as the convention).
    "skipped_revoked": ("T1070.001", "T1108", "T1562.008"),
    "skipped_orphan": ("T9998", "T9999"),
    "warnings": 5,  # 3 revoked/deprecated + 2 orphan
}

#: Re-running the SAME populate must be a complete no-op (values unchanged).
MINI_POPULATE_IDEMPOTENT_RERUN: Mapping[str, Any] = {
    "rows_upserted": len(MINI_PAIR_ROWS),
    "rows_inserted": 0,
    "rows_updated": 0,
    "rows_deleted": 0,
    "skipped_revoked": MINI_POPULATE_FIRST_RUN["skipped_revoked"],
    "skipped_orphan": MINI_POPULATE_FIRST_RUN["skipped_orphan"],
    "warnings": MINI_POPULATE_FIRST_RUN["warnings"],
}

#: Disabling zeek afterwards deletes its single stale row (set-difference).
MINI_POPULATE_DISABLE_ZEEK: Mapping[str, Any] = {
    "rows_upserted": len(MINI_PAIR_ROWS) - 1,
    "rows_inserted": 0,
    "rows_updated": 0,
    "rows_deleted": 1,
    "skipped_revoked": MINI_POPULATE_FIRST_RUN["skipped_revoked"],
    "skipped_orphan": MINI_POPULATE_FIRST_RUN["skipped_orphan"],
    "warnings": MINI_POPULATE_FIRST_RUN["warnings"],
}

#: Enabling nginx afterwards inserts T1190@nginx (projected 0.75, detectable)
#: -- initial-access flips to 1/1 detectable.
MINI_POPULATE_ENABLE_NGINX: Mapping[str, Any] = {
    "rows_upserted": len(MINI_PAIR_ROWS) + 1,
    "rows_inserted": 1,
    "rows_updated": 0,
    "rows_deleted": 0,
    "skipped_revoked": MINI_POPULATE_FIRST_RUN["skipped_revoked"],
    "skipped_orphan": MINI_POPULATE_FIRST_RUN["skipped_orphan"],
    "warnings": MINI_POPULATE_FIRST_RUN["warnings"],
}

#: Attack ids with best_confidence >= threshold on the first-run state.
MINI_DETECTABLE_IDS: tuple[str, ...] = (
    "T1047",
    "T1059.001",
    "T1059.003",
    "T1110.001",  # best 0.765 via zeek despite sub-threshold evtx/json rows
    "T1569.002",
)


# ---------------------------------------------------------------------------
# Golden expectations -- coverage_by_tactic (contract D)
# ---------------------------------------------------------------------------
# (tactic, total, detectable, pct) for all 14 tactics in canonical order,
# platform_scope="windows", threshold 0.6 inclusive. Denominators count ALL
# in-scope, non-revoked/non-deprecated techniques assigned the tactic
# (multi-tactic counted once per tactic); zero-total tactics still emit.

def _tactic_totals() -> tuple[tuple[str, int, int, float], ...]:
    scoped = {
        row[1]
        for row in MINI_TECHNIQUES
        if not row[5] and not row[6] and "windows" in {p.lower() for p in row[4]}
    }
    detectable_ids = set(MINI_DETECTABLE_IDS)
    entries = []
    for tactic in CANONICAL_TACTICS:
        members = sorted(
            row[1] for row in MINI_TECHNIQUES
            if row[1] in scoped and tactic in row[3]
        )
        det = sum(1 for aid in members if aid in detectable_ids)
        total = len(members)
        entries.append((tactic, total, det, round(det / total, 4) if total else 0.0))
    return tuple(entries)


#: Golden coverage_by_tactic snapshot for the mini dataset.
MINI_TACTIC_TOTALS: tuple[tuple[str, int, int, float], ...] = _tactic_totals()


# ---------------------------------------------------------------------------
# Golden expectations -- gaps (contract E)
# ---------------------------------------------------------------------------
# (attack_id, name, tactic, best_confidence, closable_by) ordered by
# GAP_SORT_NOTE. best_confidence is MAX across enabled-datasource rows.

def _best_conf(attack_id: str) -> float:
    return max(
        (row[3] for row in MINI_PAIR_ROWS if row[1] == attack_id),
        default=0.0,
    )


_NAMES = {row[1]: row[2] for row in MINI_TECHNIQUES}
_TACTICS_OF = {row[1]: row[3] for row in MINI_TECHNIQUES}
_TACTIC_RANK = {t: i for i, t in enumerate(CANONICAL_TACTICS)}

# Disabled formats and their best static projection per technique: the
# honest closable_by filter requires projection >= threshold (inclusive).
_DISABLED_PROJECTIONS: Mapping[str, tuple[tuple[str, float], ...]] = {
    "T1190": (("nginx", min(0.75 * TIER_EXT, CONF_CAP)),),
    # Projected 0.25 < 0.6 -> cef must NOT appear despite the mapping.
    "T1136.001": (("cef", min(0.25 * TIER_EXT, CONF_CAP)),),
}
_ENABLED = {fmt for _i, _n, fmt, en in MINI_DATASOURCES if en}


def _gaps() -> tuple[tuple[str, str, str, float, tuple[str, ...]], ...]:
    scoped_alive = [
        row for row in MINI_TECHNIQUES
        if not row[5] and not row[6] and "windows" in {p.lower() for p in row[4]}
    ]
    rows = []
    for tech in scoped_alive:
        aid = tech[1]
        best = _best_conf(aid)
        if best >= THRESHOLD:
            continue
        closable = tuple(sorted(
            fmt for fmt, proj in _DISABLED_PROJECTIONS.get(aid, ())
            if fmt not in _ENABLED and proj >= THRESHOLD
        ))
        for tactic in tech[3]:
            rows.append((aid, tech[2], tactic, best, closable))
    rows.sort(key=lambda r: (_TACTIC_RANK[r[2]], r[3], r[0]))
    return tuple(rows)


#: Golden calculate_coverage_gaps snapshot for the mini dataset (10 gaps).
MINI_GAPS: tuple[tuple[str, str, str, float, tuple[str, ...]], ...] = _gaps()


# ---------------------------------------------------------------------------
# Golden expectations -- gap clustering policy (contract F)
# ---------------------------------------------------------------------------
# Each case: (name, n_items_hint, description). Item payloads are produced
# by CLUSTER_POLICY_CASES factories below; assertions target POLICY outputs
# (cluster count, size floor, label prefix, determinism), never exact
# partitions, because centroid geometry belongs to the engine.

CLUSTER_POLICY_CASES: Mapping[str, Mapping[str, Any]] = {
    "empty": {
        "items": (),
        "expect": "returns () without invoking KMeans",
    },
    "tiny": {
        "items": ("a", "b", "c"),
        "expect": "single cluster, no KMeans call",
    },
    "separated": {
        # Two tight lexical cells (persistence-flavored vs execution-flavored
        # names) -- k>=2 must be accepted: silhouette >= 0.20 and all
        # clusters sized >= 2.
        "items": (
            "Add Office account extensions persistence",
            "Add outlook account email extensions persistence",
            "Malicious process injection api command execution",
            "Malicious dynamic linker hijacking path execution",
        ),
        "expect": ("k >= 2 accepted", "every cluster size >= 2",
                   "labels start with majority tactic + ': '"),
    },
}

#: Label template (contract F): majority tactic + top-2 distinguishing
#: keywords (mean-in-cluster minus mean-outside tf-idf > 0.05).
CLUSTER_LABEL_SPEC = "{majority_tactic}: {keyword1}/{keyword2}"

#: Summary template (contract F): exactly one sentence.
CLUSTER_SUMMARY_SPEC = (
    "{n} undetected techniques share {keyword1}/{keyword2} behavior in {tactic}."
)

#: Real-world expectation: the current ~449-gap set yields ONE cluster
#: (best mean silhouette ~0.168 across k=2..6, below the 0.20 acceptance
#: floor) -- the conservative single-cluster fallback is CORRECT behavior.
REAL_CLUSTER_FALLBACK: Mapping[str, Any] = {
    "expected_clusters": 1,
    "observed_best_silhouette": 0.168,
    "silhouette_threshold": 0.2,
    "note": "fallback to a single cluster is the correct outcome",
}


# ---------------------------------------------------------------------------
# Golden expectations -- real dataset (contracts I/N)
# ---------------------------------------------------------------------------

#: execution tactic ground truth (agent-165): 46 windows-scoped alive
#: techniques, exactly 4 detectable at threshold 0.6. All four winners are
#: extension (Tier-1) rules, so the expected detectable SET is identical
#: under raw-base and tier-adjusted populate semantics.
REAL_EXECUTION: Mapping[str, Any] = {
    "tactic": "execution",
    "total_in_scope_windows": 43,  # deprecated T1061/T1064/T1175 folded out
    "expected_detectable_ids": (
        "T1047", "T1053.005", "T1059.001", "T1059.003", "T1569.002",
    ),
    "explained_gap_note": (
        "Only PowerShell/cmd/WMI/scheduled-task/service-execution families "
        "clear 0.6 via evtx extension evidence (T1053.005 is technique-"
        "tagged execution); T1059.009 cloud-api tops out at 0.20 (heuristic) "
        "and T1053.003 at 0.3825 (syslog action-only)."
    ),
    "expected_pct": round(5 / 43, 4),  # 0.1163
}

#: Attack ids currently targeted ONLY by rules whose technique is revoked in
#: the DB; populate must route them through skipped_revoked (contract I pins
#: T1562.008 explicitly -- M016 awaits retargeting to T1685.002).
REAL_REVOKED_SKIP_IDS: tuple[str, ...] = ()
# Formerly (T1070.001, T1562.001, T1562.008) - owner retargeted every
# affected row to live v19 successors (T1685.005 / T1685 / T1685.002),
# so the curated CSV no longer touches revoked/deprecated techniques.

#: Persistence-tagged deprecated techniques (subset of the 12 deprecated
#: bundle attack-patterns) that the deprecated-as-revoked fix (G1) removes
#: from persistence denominators: 117 active -> 113.
REAL_DEPRECATED_PERSISTENCE_IDS: tuple[str, ...] = (
    "T1034", "T1053.004", "T1062", "T1108",
)

 #: Honest closable_by examples measured in Wave 1 (contract E).
REAL_CLOSABLE_EXAMPLES: tuple[tuple[str, tuple[str, ...]], ...] = (
    # M082 0.75 / M083 boundary 0.60, both nginx (disabled): closes it.
    ("T1190", ("nginx",)),
    # Naive any-mapping logic would promise cef; static projection 0.25
    # kills the promise (agent-195).
    ("T1136.001", ()),
    ("T1046", ()),
)

#: Universe counts measured read-only on db/coverage.db (v19 bundle).
REAL_UNIVERSE_COUNTS: Mapping[str, int] = {
    "techniques_total": 858,
    "revoked": 149,
    "windows_scoped_alive": 483,
    "platform_windows_tagged": 591,
    "canonical_platform_values": 12,
}

#: Independent gap-count estimates under slightly different predicates;
#: integration assertions should use a range, not one magic number.
REAL_GAP_COUNT_RANGE: tuple[int, int] = (438, 461)

#: Degenerate-scenario shapes (agent-197): zero explicitly-enabled sources
#: fail closed to 14 zero rows; an empty-but-present schema yields 14 zero
#: rows and no gaps. Stored as (tactic, total, detectable, pct) triples.
SCENARIO_ZERO_ENABLED: tuple[tuple[str, int, int, float], ...] = tuple(
    (tactic, 0, 0, 0.0) for tactic in CANONICAL_TACTICS
)

#: Empty DB (tables exist, 0 techniques): same zero rows, gaps = ().
SCENARIO_EMPTY_DB: Mapping[str, Any] = {
    "coverage_by_tactic": SCENARIO_ZERO_ENABLED,
    "gaps": (),
}


# ---------------------------------------------------------------------------
# Config extension goldens (contract H)
# ---------------------------------------------------------------------------

#: Optional top-level ``clustering`` block; load_config fills these exact
#: defaults when the block is absent and must ValueError on bad types or
#: out-of-range values.
CONFIG_CLUSTERING_DEFAULTS: Mapping[str, Any] = {
    "min_clusterable": 4,
    "k_max": 6,
    "silhouette_threshold": 0.2,
    "max_vocab": 200,
    "seed": 42,
}

#: (yaml_snippet_fragment, why_invalid) samples for validator tests.
CONFIG_INVALID_CLUSTERING_CASES: tuple[tuple[str, str], ...] = (
    ("clustering:\n  min_clusterable: 1\n", "below minimum 4"),
    ("clustering:\n  k_max: true\n", "bool is not an int"),
    ("clustering:\n  silhouette_threshold: 1.5\n", "outside [0, 1]"),
    ("clustering:\n  max_vocab: -5\n", "negative vocabulary cap"),
    ("clustering:\n  seed: forty-two\n", "seed is not an int"),
)


# ---------------------------------------------------------------------------
# Mini STIX bundle (loader-fix tests, contract G)
# ---------------------------------------------------------------------------

def make_stix_attack_pattern(
    stix_id: str,
    attack_id: str,
    name: str,
    *,
    phases: Sequence[str] = (),
    platforms: Sequence[str] = (),
    revoked: bool = False,
    deprecated: bool = False,
    subtechnique: bool | None = None,
    description: str | None = None,
) -> dict[str, Any]:
    """Build a minimal v19-style ``attack-pattern`` STIX object.

    Args:
        stix_id: Full STIX identifier (``attack-pattern--uuid``).
        attack_id: External ATT&CK id such as ``T1059.001``.
        name: Technique display name.
        phases: ``mitre-attack`` kill-chain phase names (pre-aliasing).
        platforms: ``x_mitre_platforms`` values with canonical casing.
        revoked: Value for the STIX ``revoked`` property.
        deprecated: Value for ``x_mitre_deprecated`` (contract G1).
        subtechnique: ``x_mitre_is_subtechnique``; inferred from the dot in
            ``attack_id`` when left as ``None``.
        description: Optional technique description.

    Returns:
        A plain dict shaped like a stripped-down STIX attack-pattern, ready
        to feed :func:`src.attack_data.loader.load_all` via a bundle dict.
    """
    obj: dict[str, Any] = {
        "type": "attack-pattern",
        "id": stix_id,
        "name": name,
        "kill_chain_phases": [
            {"kill_chain_name": "mitre-attack", "phase_name": phase}
            for phase in phases
        ],
        "x_mitre_platforms": list(platforms),
        "revoked": revoked,
        "x_mitre_deprecated": deprecated,
        "external_references": [
            {"source_name": "mitre-attack", "external_id": attack_id}
        ],
    }
    obj["x_mitre_is_subtechnique"] = (
        ("." in attack_id) if subtechnique is None else subtechnique
    )
    if description is not None:
        obj["description"] = description
    return obj


#: Mini bundle exercising the loader fixes: stealth/defense-impairment
#: aliases (G2), an unknown phase (counted in unknown_phase_count), a
#: deprecated technique (treated as revoked, G1) and a plainly revoked one.
MINI_STIX_BUNDLE: tuple[dict[str, Any], ...] = (
    make_stix_attack_pattern(
        _STIX.format(101), "T1036", "Masquerading",
        phases=("stealth",), platforms=("Windows",),
    ),
    make_stix_attack_pattern(
        _STIX.format(102), "T1685.002", "Impair Defenses",
        phases=("defense-impairment",), platforms=("IaaS",), subtechnique=True,
    ),
    make_stix_attack_pattern(
        _STIX.format(103), "T1059.001", "PowerShell",
        phases=("execution",), platforms=("Windows",), subtechnique=True,
    ),
    make_stix_attack_pattern(
        _STIX.format(104), "T1108", "Access Removal",
        phases=("persistence",), platforms=("Windows",), deprecated=True,
    ),
    make_stix_attack_pattern(
        _STIX.format(105), "T1562.008", "Disable Cloud Logs",
        phases=("defense-evasion",), platforms=("IaaS",), subtechnique=True,
        revoked=True,
    ),
    make_stix_attack_pattern(
        _STIX.format(106), "T1595", "Active Scanning",
        # Unknown phase must be dropped but counted (contract G2).
        phases=("reconnaissance", "totally-unknown-phase"), platforms=("PRE",),
    ),
)

#: attack_id -> expected tactics AFTER aliasing + allowlist (G2).
EXPECTED_ALIAS_TACTICS: Mapping[str, tuple[str, ...]] = {
    "T1036": ("defense-evasion",),
    "T1685.002": ("defense-evasion",),
    "T1059.001": ("execution",),
    "T1108": ("persistence",),
    "T1562.008": ("defense-evasion",),
    "T1595": ("reconnaissance",),
}

#: Number of dropped-but-counted unknown kill-chain phases in MINI_STIX_BUNDLE.
EXPECTED_UNKNOWN_PHASE_COUNT = 1


# ---------------------------------------------------------------------------
# Config fixture (mini dataset view of config.yaml)
# ---------------------------------------------------------------------------

#: Normalized config dict equivalent to the shipped config.yaml plus the
#: clustering defaults (contract H). Plain dict is intentional: it mirrors
#: what load_config returns (an internal input, not a public analyzer
#: return type bound by contract A).
MINI_CONFIG: Mapping[str, Any] = {
    "platform_scope": "windows",
    "detection_confidence_threshold": THRESHOLD,
    "enabled_log_sources": {
        "evtx": True,
        "syslog": True,
        "cef": False,
        "leef": False,
        "json": True,
        "aws_cloudtrail": True,
        "nginx": False,
        "zeek": True,
    },
    "clustering": dict(CONFIG_CLUSTERING_DEFAULTS),
}


# ---------------------------------------------------------------------------
# File builders
# ---------------------------------------------------------------------------

_MAPPING_CSV_COLUMNS: tuple[str, ...] = (
    "mapping_id", "source_format", "event_action_pattern", "ext_keys",
    "ext_value_pattern", "match_type", "is_core", "technique_id", "tactic",
    "base_confidence", "visibility_hint", "evidence_ref", "sigma_rule_id",
    "notes",
)


def write_mini_mappings_csv(path: str | Path) -> Path:
    """Write the mini mapping rules as a load_mappings-compatible CSV.

    Args:
        path: Destination CSV path (typically ``tmp_path / "mappings.csv"``).

    Returns:
        The written path, for chaining with ``load_mappings(str(path))``.
    """
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(_MAPPING_CSV_COLUMNS)
        for row in MINI_RULES:
            rendered = list(row[:6])
            rendered.append("true" if row[6] else "false")  # is_core
            rendered.extend(row[7:10])
            rendered.append(str(row[10]))  # visibility_hint int
            rendered.extend(row[11:])
            writer.writerow(rendered)
    logger.debug("Wrote %d mini mapping rules to %s", len(MINI_RULES), dest)
    return dest


def write_mini_config_yaml(path: str | Path) -> Path:
    """Write MINI_CONFIG as a load_config-compatible YAML file.

    Stdlib-only renderer (no PyYAML dependency at fixture level), matching
    the conftest.py convention.

    Args:
        path: Destination YAML path (typically ``tmp_path / "config.yaml"``).

    Returns:
        The written path, for chaining with ``load_config(str(path))``.
    """
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    sources = MINI_CONFIG["enabled_log_sources"]
    clustering = MINI_CONFIG["clustering"]
    lines = [
        f"platform_scope: {MINI_CONFIG['platform_scope']}",
        f"detection_confidence_threshold: {THRESHOLD}",
        "enabled_log_sources:",
    ]
    lines.extend(f"  {fmt}: {str(bool(en)).lower()}" for fmt, en in sources.items())
    lines.append("clustering:")
    lines.extend(f"  {key}: {val}" for key, val in clustering.items())
    dest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    logger.debug("Wrote mini config to %s", dest)
    return dest


# ---------------------------------------------------------------------------
# Generic builders bridging to engine dataclasses
# ---------------------------------------------------------------------------

def build_frozen(dc_cls: type, values: Mapping[str, Any]) -> Any:
    """Construct ``dc_cls`` from golden ``values``, strictly.

    Extra keys raise ValueError (catches fixture typos early); missing
    required fields surface as the dataclass's own TypeError.

    Args:
        dc_cls: Target (frozen) dataclass class from the engine module.
        values: Field-name -> value mapping, e.g. MINI_POPULATE_FIRST_RUN.

    Returns:
        The constructed dataclass instance.
    """
    known = {f.name for f in dataclasses.fields(dc_cls)}
    extras = sorted(set(values) - known)
    if extras:
        raise ValueError(
            f"{dc_cls.__name__} has no field(s) {extras}; "
            f"known fields: {sorted(known)}"
        )
    return dc_cls(**values)


def build_mini_tactic_coverage(cls: type) -> tuple[Any, ...]:
    """Build the golden per-tactic snapshot as instances of ``cls``.

    Args:
        cls: The engine's TacticCoverage frozen dataclass; must accept
            ``tactic``, ``total``, ``detectable`` and ``pct`` keywords.

    Returns:
        A tuple of 14 instances in canonical tactic order (contract A/D).
    """
    return tuple(
        cls(tactic=tactic, total=total, detectable=detectable, pct=pct)
        for tactic, total, detectable, pct in MINI_TACTIC_TOTALS
    )


def build_mini_coverage_gaps(cls: type) -> tuple[Any, ...]:
    """Build the golden gap snapshot as instances of ``cls``.

    Args:
        cls: The engine's Gap frozen dataclass; must accept
            ``technique_attack_id``, ``name``, ``tactic``,
            ``best_confidence`` and ``closable_by`` keywords.

    Returns:
        Gaps ordered per GAP_SORT_NOTE, ready for equality comparison
        against ``calculate_coverage_gaps`` output on the mini dataset.
    """
    return tuple(
        cls(
            technique_attack_id=attack_id,
            name=name,
            tactic=tactic,
            best_confidence=best,
            closable_by=closable,
        )
        for attack_id, name, tactic, best, closable in MINI_GAPS
    )


# ---------------------------------------------------------------------------
# Contract-A hashability audit
# ---------------------------------------------------------------------------

def ensure_contract_a(value: Any, _path: str = "root") -> None:
    """Recursively verify the Wave-1 hashability contract (A).

    Allowed leaves: ``None|bool|int|float|str``. Allowed containers:
    ``tuple`` (any depth, elements audited recursively), ``frozenset``,
    and frozen dataclasses whose field values are audited recursively.
    ``list``, ``dict``, ``set``, generators and arbitrary objects raise
    TypeError naming the offending path.

    Args:
        value: Object tree returned by a public analyzer.
        _path: Internal dotted path for error messages.

    Raises:
        TypeError: If any node violates the contract.
    """
    if value is None or isinstance(value, (bool, int, float, str)):
        return
    if isinstance(value, tuple):
        for i, item in enumerate(value):
            ensure_contract_a(item, f"{_path}[{i}]")
        return
    if isinstance(value, frozenset):
        for item in value:
            ensure_contract_a(item, f"{_path}{{}}")
        return
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        if not hasattr(type(value), "__hash__") or type(value).__hash__ is None:
            raise TypeError(f"{_path}: dataclass {type(value).__name__} is unhashable")
        for f in dataclasses.fields(value):
            ensure_contract_a(getattr(value, f.name), f"{_path}.{f.name}")
        return
    raise TypeError(
        f"{_path}: forbidden type {type(value).__name__!r} violates "
        "contract A (None|bool|int|float|str|tuple|frozen-dataclass only)"
    )


# ---------------------------------------------------------------------------
# Self-consistency guard
# ---------------------------------------------------------------------------

def assert_mini_dataset_consistent() -> None:
    """Cross-check the hand-computed mini goldens against each other.

    Raises:
        AssertionError: On any internal inconsistency (broken invariant
            between rules, techniques, pairs, tactic totals and gaps).
    """
    # Every pair references an alive in-dataset technique and an enabled
    # datasource; confidence respects cap and detectability threshold.
    alive = {r[0] for r in MINI_TECHNIQUES if not r[5] and not r[6]}
    enabled_ds = {_DS_ID[f] for f in _ENABLED}
    for stix_id, attack_id, ds_id, conf, det in MINI_PAIR_ROWS:
        assert stix_id == _ATTACK_ID_TO_STIX[attack_id], attack_id
        assert stix_id in alive, f"pair for dead technique {attack_id}"
        assert ds_id in enabled_ds, f"pair on disabled source {attack_id}"
        assert 0.0 <= conf <= CONF_CAP, f"cap violated for {attack_id}"
        assert det == (conf >= THRESHOLD), f"threshold mismatch {attack_id}"
    # Detectable-id list agrees with pair rows.
    from_pairs = tuple(sorted({r[1] for r in MINI_PAIR_ROWS if r[4]}))
    assert from_pairs == MINI_DETECTABLE_IDS, (from_pairs, MINI_DETECTABLE_IDS)
    # Tactic totals sum to the scoped-alive assignment count.
    scoped_alive = [
        r for r in MINI_TECHNIQUES
        if not r[5] and not r[6] and "windows" in {p.lower() for p in r[4]}
    ]
    assignments = sum(len(r[3]) for r in scoped_alive)
    assert sum(t for _t, t, _d, _p in MINI_TACTIC_TOTALS) == assignments
    assert sum(d for _t, _n, d, _p in MINI_TACTIC_TOTALS) == len(MINI_DETECTABLE_IDS)
    assert len(MINI_TACTIC_TOTALS) == len(CANONICAL_TACTICS) == 14
    # Gaps: complement of detectables among scoped alive, split per tactic,
    # sorted per GAP_SORT_NOTE, and every gap confidence is below threshold.
    detected = set(MINI_DETECTABLE_IDS)
    expected_gap_count = sum(
        len(r[3]) for r in scoped_alive if r[1] not in detected
    )
    assert len(MINI_GAPS) == expected_gap_count
    keys = [(_TACTIC_RANK[g[2]], g[3], g[0]) for g in MINI_GAPS]
    assert keys == sorted(keys), "gap ordering violates " + GAP_SORT_NOTE
    for _aid, _name, _tactic, best, closable in MINI_GAPS:
        assert best < THRESHOLD
        assert isinstance(closable, tuple) and all(c not in _ENABLED for c in closable)
    assert ("T1190", "Exploit Public-Facing Application", "initial-access",
            0.0, ("nginx",)) in MINI_GAPS, "honest-filter positive lost"
    assert all(g[4] != ("cef",) for g in MINI_GAPS), "naive cef promise leaked"
    # Populate reports agree with the pair set.
    assert MINI_POPULATE_FIRST_RUN["rows_upserted"] == len(MINI_PAIR_ROWS)
    logger.info(
        "mini dataset consistent: %d techniques, %d rules, %d pairs, "
        "%d gaps, %d/%d detectable",
        len(MINI_TECHNIQUES), len(MINI_RULES), len(MINI_PAIR_ROWS),
        len(MINI_GAPS), len(MINI_DETECTABLE_IDS), assignments,
    )


if __name__ == "__main__":  # pragma: no cover - manual self-check entry point
    logging.basicConfig(level=logging.DEBUG)
    assert_mini_dataset_consistent()
    print("tactic totals:")
    for row in MINI_TACTIC_TOTALS:
        print("  ", row)
    print("gaps:")
    for gap in MINI_GAPS:
        print("  ", gap)
    print("OK")
