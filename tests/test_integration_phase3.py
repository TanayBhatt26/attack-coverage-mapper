"""Phase 3 integration tests: coverage engine, populate idempotency, gaps, clustering.

Exercises the Wave-2 Phase-3 deliverables end-to-end against disposable
SQLite databases (never ``db/coverage.db``):

    data/attack_mappings.csv (real, 83 rows)
        + techniques universe rebuilt from the pinned STIX cache
        -> analysis.coverage_analyzer.populate_technique_coverage()
        -> analysis.coverage_analyzer.load_coverage_rows()
        -> analysis.coverage_analyzer.coverage_by_tactic()
        -> analysis.coverage_analyzer.calculate_coverage_gaps()

plus the clustering layer (``analysis.gap_clustering``), the loader data
fixes in ``attack_data.loader`` and the ``clustering`` config extension in
``config_loader.load_config``.

Contract provenance for every hardcoded number:

* Populate-time confidence semantics (contract D): per
  ``(technique, log_format)`` row confidence = max over that format's
  mapping rules of ``base_confidence * tier_mult``, tiers derived
  statically from rule shape -- ``heuristic`` -> x0.40 (wins over shape),
  ext_keys present -> x1.00, action-pattern-only -> x0.85 -- capped at
  0.95, ``exists`` rows ignore their value pattern. This is deliberately
  NOT event-time scoring; the golden table in
  ``research/p3-wave1-full-results.md`` (agent-225) lists raw base
  confidences and is recomputed here under the tier-multiplier contract
  (e.g. T1110.001@zeek = 0.90 x 0.85 = 0.765).
* The execution denominator 46 / detectable set {T1059.001, T1059.003,
  T1047, T1569.002} @ 0.70-0.75 comes from the same research file
  (agents 165/225), measured on the v19 STIX snapshot shipped at
  ``data/attack_stix/enterprise-attack.json`` (bundle_date 2026-08-04).
  The universe builder below intentionally replicates the PRE-fix loader
  semantics (plain ``ENTERPRISE_TACTICS`` allowlist, no phase aliasing,
  no deprecation folding) so those Wave-1 numbers stay valid; the
  aliasing/deprecation fixes are covered separately against
  ``_technique_rows`` directly.
* M016 targets revoked T1562.008 until the owner applies the pending
  retarget to T1685.002; populate must route it through the revoked-skip
  path (contract I). The same holds for M014/M033 -> revoked T1070.001
  and M044/M061 -> revoked T1562.001 -- together the full revoked-skip
  set for the curated CSV on this snapshot.

Interface notes (matched to the landed implementations):

* ``populate_technique_coverage(session, rules, config)`` consumes already
  validated :class:`~parser.mappings_io.MappingRule` sequences and flushes
  without committing; these tests commit explicitly.
* ``DataSourceType`` provisioning is owned by populate itself (it seeds
  the 8 canonical formats mirroring ``enabled_log_sources``); tests never
  pre-seed datasource rows and always join through ``log_format``.
* ``PopulateReport.rows_upserted`` counts rows actually written this run
  (``rows_inserted + rows_updated``), so a clean no-op rerun reports 0.
* ``skipped_revoked`` / ``skipped_orphan`` hold technique ATTACK ids;
  ``warnings`` counts revoked skips + orphan skips + unknown-format rules.
* Disabled log formats are driven exclusively by
  ``config['enabled_log_sources']`` (the dashboard toggle beat); rules of
  disabled formats are excluded silently, unknown source formats warn.
* ``CoverageRow`` exposes ``attack_id`` / ``scope_hit``; ``Gap`` exposes
  ``technique_attack_id`` (contract E naming).

Offline only; writes confined to pytest tmp dirs; no network, no
subprocess/eval/exec.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable, Sequence

import pytest
import yaml

from analysis import coverage_analyzer
from analysis.gap_clustering import ClusteringParams, GapItem, cluster_gaps
from attack_data.loader import ENTERPRISE_TACTICS, LoadReport, _technique_rows
from config_loader import load_config
from database.models import (
    Base,
    DataSourceType,
    Technique,
    TechniqueCoverage,
)
from database.session import make_engine
from parser.mappings_io import MappingRule, load_mappings

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.integration]

REPO_ROOT = Path(__file__).resolve().parents[1]
MAPPINGS_CSV = REPO_ROOT / "data" / "attack_mappings.csv"
STIX_CACHE = REPO_ROOT / "data" / "attack_stix" / "enterprise-attack.json"
REPO_CONFIG_YAML = REPO_ROOT / "config.yaml"

#: Canonical ATT&CK Enterprise tactic order (contract D).
CANONICAL_TACTICS: tuple[str, ...] = coverage_analyzer.CANONICAL_TACTICS

#: Contract H defaults for the optional top-level ``clustering`` section.
CLUSTERING_DEFAULTS: dict[str, Any] = {
    "min_clusterable": 4,
    "k_max": 6,
    "silhouette_threshold": 0.2,
    "max_vocab": 200,
    "seed": 42,
}

#: Log formats disabled by the repo's own ``config.yaml``.
DEFAULT_DISABLED_FORMATS: frozenset[str] = frozenset({"cef", "leef", "nginx"})
KNOWN_FORMATS: tuple[str, ...] = (
    "evtx",
    "syslog",
    "cef",
    "leef",
    "json",
    "aws_cloudtrail",
    "nginx",
    "zeek",
)

#: Golden per-(technique, format) populate rows under DEFAULT repo config,
#: recomputed from the real CSV with static tier multipliers (see module
#: docstring). detectable = confidence >= 0.6 inclusive.
GOLDEN_POPULATE_ROWS: tuple[tuple[str, str, float, bool], ...] = (
    # evtx winners (per-format max over the evtx rules M001-M047)
    ("T1059.001", "evtx", 0.75, True),
    ("T1059.003", "evtx", 0.70, True),
    ("T1047", "evtx", 0.70, True),
    ("T1569.002", "evtx", 0.70, True),
    ("T1053.005", "evtx", 0.75, True),
    ("T1543.003", "evtx", 0.85, True),
    ("T1136.001", "evtx", 0.85, True),
    ("T1078.003", "evtx", 0.85, True),
    ("T1021.002", "evtx", 0.85, True),
    ("T1021.001", "evtx", 0.60, True),  # boundary-inclusive threshold
    ("T1112", "evtx", 0.70, True),
    ("T1082", "evtx", 0.65, True),
    ("T1057", "evtx", 0.60, True),
    ("T1531", "evtx", 0.60, True),
    ("T1110.003", "evtx", 0.6375, True),
    ("T1078", "evtx", 0.55, False),  # max(.3825 t2, .35, .55, .55)
    ("T1033", "evtx", 0.55, False),
    ("T1110", "evtx", 0.50, False),  # max(M024 .50, M040 .3825, M041 .40)
    ("T1110.001", "evtx", 0.51, False),  # M001 action-only 0.60x0.85
    # aws_cloudtrail
    ("T1110", "aws_cloudtrail", 0.70, True),
    ("T1098.001", "aws_cloudtrail", 0.70, True),
    ("T1098.003", "aws_cloudtrail", 0.7225, True),  # M018 action-only .85x.85
    ("T1136.003", "aws_cloudtrail", 0.90, True),
    ("T1531", "aws_cloudtrail", 0.85, True),  # M060 outranks evtx M039 .60
    ("T1059.009", "aws_cloudtrail", 0.20, False),  # M056 heuristic .50x.40
    # json
    ("T1110.003", "json", 0.80, True),  # M081 tier1 outranks evtx 0.6375
    ("T1110.001", "json", 0.18, False),  # M080 heuristic .45x.40
    # zeek
    ("T1110.001", "zeek", 0.765, True),  # max(M019 .7225, M020 .765)
    ("T1046", "zeek", 0.68, True),  # max(M062 .2975, M063/M064 .68, M065 .18)
    ("T1071.004", "zeek", 0.65, True),
    ("T1048", "zeek", 0.70, True),
    ("T1496", "zeek", 0.70, True),
    # syslog
    ("T1548.003", "syslog", 0.70, True),
    ("T1053.003", "syslog", 0.3825, False),  # M075 action-only .45x.85
)

#: Mapping targets revoked on the pinned cache snapshot -> skipped+WARNed.
GOLDEN_REVOKED_TARGETS: frozenset[str] = frozenset(
    {"T1070.001", "T1562.001", "T1562.008"}
)

#: Wave-1 golden execution slice (contract I/N): windows-scope alive
#: execution techniques total 46. The research file lists FOUR detectable
#: ids (T1059.001/T1059.003/T1047/T1569.002 @ 0.70-0.75) because agent-165
#: enumerated detectability by the CSV rules' ``tactic`` COLUMN; the engine
#: buckets by each technique's tactics JSON (contract D), and T1053.005 --
#: detected at 0.75 via evtx -- legitimately carries ``execution`` there
#: too. Empirically verified against the pinned cache snapshot: 5/46.
GOLDEN_EXECUTION_TOTAL = 46
GOLDEN_EXECUTION_DETECTABLE_IDS = frozenset(
    {"T1059.001", "T1059.003", "T1047", "T1569.002", "T1053.005"}
)
GOLDEN_EXECUTION_DETECTABLE_CONFIDENCES: dict[str, float] = {
    "T1059.001": 0.75,
    "T1059.003": 0.70,
    "T1047": 0.70,
    "T1569.002": 0.70,
    "T1053.005": 0.75,
}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

_PRIMITIVE_TYPES = (bool, int, float, str, type(None))


def assert_frozen_hashable(value: Any, path: str = "root") -> None:
    """Recursively assert contract A on a public analyzer return value.

    Accepts only primitives, tuples (at any depth) and (necessarily frozen)
    dataclass instances; anything else -- list/dict/set especially -- fails.
    Also proves native ``hash()`` works on every dataclass visited.
    """
    if isinstance(value, _PRIMITIVE_TYPES):
        return
    if isinstance(value, tuple):
        for index, item in enumerate(value):
            assert_frozen_hashable(item, f"{path}[{index}]")
        return
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        hash(value)  # TypeError here means a mutable/unhashable field leaked
        for field in dataclasses.fields(value):
            assert_frozen_hashable(getattr(value, field.name), f"{path}.{field.name}")
        return
    raise AssertionError(
        f"contract A violation at {path}: unexpected type {type(value)!r}"
    )


def default_cfg(**overrides: Any) -> dict[str, Any]:
    """Build an analyzer config dict mirroring the repo ``config.yaml``.

    Keyword overrides merge shallowly; ``enabled_log_sources`` merges per
    key over an all-enabled base so callers can flip single formats.
    """
    cfg: dict[str, Any] = {
        "platform_scope": "windows",
        "detection_confidence_threshold": 0.6,
        **overrides,
    }
    merged = {fmt: True for fmt in KNOWN_FORMATS}
    merged.update(overrides.get("enabled_log_sources", {}))
    cfg["enabled_log_sources"] = merged
    return cfg


def coverage_pairs_by_format(session: Any) -> dict[tuple[str, str], tuple[float, bool]]:
    """Snapshot persisted technique_coverage as {(attack_id, format): (conf, det)}.

    Joins through ``log_format`` so the test never depends on datasource
    ids or display names.
    """
    found: dict[tuple[str, str], tuple[float, bool]] = {}
    for cov, ds in (
        session.query(TechniqueCoverage, DataSourceType)
        .join(DataSourceType, TechniqueCoverage.datasource_id == DataSourceType.id)
        .all()
    ):
        key = (cov.technique_attack_id, ds.log_format)
        assert key not in found, f"duplicate pair rows for {key}"
        found[key] = (float(cov.detection_confidence), bool(cov.is_detectable))
    return found


def make_rule(
    rid: str,
    fmt: str,
    base: float,
    tech: str,
    tactic: str,
    *,
    ext: str = "",
    action: str | None = None,
    match_type: str = "regex",
) -> MappingRule:
    """Build one synthetic :class:`MappingRule` (regexes compiled here)."""
    return MappingRule(
        mapping_id=rid,
        source_format=fmt,
        event_action_re=None if action is None else re.compile(action),
        ext_keys=tuple(k.strip().lower() for k in ext.split(";") if k.strip()),
        ext_value_re=None,
        match_type=match_type,
        is_core=True,
        technique_id=tech,
        tactic=tactic,
        base_confidence=base,
        visibility_hint=3,
        evidence_ref="synthetic",
        sigma_rule_id=None,
        notes="phase-3 integration fixture",
    )


def make_gap_item(tid: str, tactic: str, description: str = "", name: str = "") -> GapItem:
    """Build a :class:`GapItem` via the contracted keyword surface."""
    return GapItem(
        technique_attack_id=tid,
        name=name or f"Synthetic gap technique {tid}",
        tactic=tactic,
        description=description or f"{tid} adversary behavior tokens",
    )


@lru_cache(maxsize=1)
def cached_universe(cache_path_text: str) -> tuple[dict[str, Any], ...]:
    """Extract the technique universe from the STIX cache (pre-fix semantics).

    Replicates the Phase-1 loader's PRE-fix behaviour deliberately: tactics
    filtered by the plain ``ENTERPRISE_TACTICS`` allowlist (no stealth /
    defense-impairment aliasing), ``revoked`` copied verbatim (deprecated-
    not-revoked objects stay active). Cached because the bundle is ~31 MB.
    """
    data = json.loads(Path(cache_path_text).read_text(encoding="utf-8"))
    external_id_re = re.compile(r"^T\d{4}(\.\d{3})?$")
    universe: list[dict[str, Any]] = []
    for obj in data:
        if obj.get("type") != "attack-pattern":
            continue
        attack_id = None
        for ref in obj.get("external_references", []) or []:
            candidate = ref.get("external_id")
            if candidate and external_id_re.match(candidate):
                attack_id = candidate
                break
        if not attack_id:
            continue
        phases = [
            kc.get("phase_name")
            for kc in obj.get("kill_chain_phases", []) or []
            if kc.get("kill_chain_name") == "mitre-attack"
        ]
        is_sub = bool(obj.get("x_mitre_is_subtechnique", False))
        universe.append(
            {
                "stix_id": obj["id"],
                "attack_id": attack_id,
                "name": obj.get("name", ""),
                "description": obj.get("description"),
                "tactics": tuple(t for t in phases if t in ENTERPRISE_TACTICS),
                "platforms": tuple(obj.get("x_mitre_platforms") or []),
                "is_subtechnique": is_sub,
                "parent_attack_id": (
                    attack_id.rsplit(".", 1)[0]
                    if is_sub and "." in attack_id
                    else None
                ),
                "revoked": bool(obj.get("revoked", False)),
            }
        )
    logger.info("Extracted %d techniques from STIX cache", len(universe))
    return tuple(universe)


def build_db(tmp_dir: Path, name: str, techniques: Iterable[dict[str, Any]]):
    """Create a fresh SQLite engine + schema seeded with ``techniques``."""
    engine = make_engine(f"sqlite:///{tmp_dir / name}")
    Base.metadata.create_all(engine)
    import sqlalchemy.orm  # local import keeps module imports flat

    factory = sqlalchemy.orm.sessionmaker(bind=engine)
    session = factory()
    for row in techniques:
        session.add(
            Technique(
                stix_id=row["stix_id"],
                attack_id=row["attack_id"],
                name=row["name"],
                description=row.get("description"),
                tactics=list(row.get("tactics", ())),
                platforms=list(row.get("platforms", ())),
                detection_strategy_refs=[],
                is_subtechnique=bool(row.get("is_subtechnique", False)),
                parent_attack_id=row.get("parent_attack_id"),
                revoked=bool(row.get("revoked", False)),
            )
        )
    session.commit()
    return engine, session


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def synth_env(tmp_path: Path):
    """Small handcrafted universe exercising every populate/gap edge case.

    Techniques (windows scope unless noted):

    - T1000 execution / Windows          -> X001 evtx ext base 1.00 (.95 cap)
    - T1001 execution+persistence / Win,Linux
                                         -> X002 evtx action .60 (.51)
                                         -> X003 evtx ext .60 (.60 boundary)
                                         -> X004 json heuristic .90 (.36)
    - T1002 execution / Linux            (out of scope)
    - T1003 persistence / Windows revoked (X010 targets it)
    - T1004 discovery+impact / Windows   -> X005 zeek ext .80
    - T1005 command-and-control / Windows-> X006 cef (disabled; closable)
    - T1006 exfiltration / Windows       -> X007 leef .50 (disabled; projected
                                            0.425 < threshold => NOT closable)
    - T1008 resource-development / Win,macOS (in scope, unmapped)

    X008 uses unknown source format ``arcsight`` (skip + warn) and X009
    targets unresolvable ``T9999`` (orphan skip). Populated with cef/leef/
    nginx disabled like the repo config.
    """
    techniques = [
        ("attack-pattern--s01", "T1000", "Alpha Execute", ("execution",), ("Windows",), False),
        ("attack-pattern--s02", "T1001", "Dual Move",
         ("execution", "persistence"), ("Windows", "Linux"), False),
        ("attack-pattern--s03", "T1002", "Linux Only", ("execution",), ("Linux",), False),
        ("attack-pattern--s04", "T1003", "Revoked Persistence",
         ("persistence",), ("Windows",), True),
        ("attack-pattern--s05", "T1004", "Discover Impact",
         ("discovery", "impact"), ("Windows",), False),
        ("attack-pattern--s06", "T1005", "C2 Beacon",
         ("command-and-control",), ("Windows",), False),
        ("attack-pattern--s07", "T1006", "Exfil Attempt",
         ("exfiltration",), ("Windows",), False),
        ("attack-pattern--s08", "T1008", "Mixed ResDev",
         ("resource-development",), ("Windows", "macOS"), False),
    ]
    rows = [
        {
            "stix_id": sid,
            "attack_id": aid,
            "name": name,
            "description": "",
            "tactics": tactics,
            "platforms": platforms,
            "is_subtechnique": False,
            "parent_attack_id": None,
            "revoked": revoked,
        }
        for sid, aid, name, tactics, platforms, revoked in techniques
    ]
    engine, session = build_db(tmp_path, "synth.db", rows)

    base_rules = [
        make_rule("X001", "evtx", 1.00, "T1000", "execution", ext="newprocessname"),
        make_rule("X002", "evtx", 0.60, "T1001", "persistence",
                  action=r"^logon_failure$"),
        make_rule("X003", "evtx", 0.60, "T1001", "persistence", ext="cmdline"),
        make_rule("X004", "json", 0.90, "T1001", "persistence",
                  match_type="heuristic"),
        make_rule("X005", "zeek", 0.80, "T1004", "discovery", ext="query"),
        make_rule("X006", "cef", 1.00, "T1005", "command-and-control",
                  action=r"^deny$"),
        make_rule("X007", "leef", 0.50, "T1006", "exfiltration",
                  action=r"^authfail$"),
        make_rule("X008", "arcsight", 0.90, "T1000", "execution", ext="foo"),
        make_rule("X009", "evtx", 0.90, "T9999", "persistence", ext="bar"),
        make_rule("X010", "evtx", 0.90, "T1003", "persistence", ext="baz"),
    ]
    cfg = default_cfg(enabled_log_sources={"cef": False, "leef": False, "nginx": False})
    report = coverage_analyzer.populate_technique_coverage(
        session, base_rules, cfg
    )
    session.commit()
    env = {
        "engine": engine,
        "session": session,
        "cfg": cfg,
        "rules": base_rules,
        "report": report,
    }
    try:
        yield env
    finally:
        session.close()
        engine.dispose()


@pytest.fixture
def golden_env(tmp_path: Path):
    """Real-CSV environment: STIX-cache universe + real mappings + repo cfg.

    Function-scoped so mutation tests never contaminate each other; the
    expensive JSON parse is cached module-wide.
    """
    universe = cached_universe(str(STIX_CACHE))
    engine, session = build_db(tmp_path, "golden.db", universe)
    cfg = load_config(str(REPO_CONFIG_YAML))
    rules = load_mappings(str(MAPPINGS_CSV))
    report = coverage_analyzer.populate_technique_coverage(session, rules, cfg)
    session.commit()
    env = {
        "engine": engine,
        "session": session,
        "cfg": cfg,
        "rules": rules,
        "report": report,
    }
    try:
        yield env
    finally:
        session.close()
        engine.dispose()


# ---------------------------------------------------------------------------
# (H) config extension
# ---------------------------------------------------------------------------


class TestConfigClusteringExtension:
    """Optional top-level ``clustering`` section: defaults + validation."""

    def _write(self, tmp_path: Path, payload: dict[str, Any]) -> str:
        path = tmp_path / "config.yaml"
        path.write_text(yaml.safe_dump(payload), encoding="utf-8")
        return str(path)

    def test_absent_section_fills_full_defaults(self, tmp_path: Path) -> None:
        cfg = load_config(self._write(tmp_path, {}))
        assert cfg["clustering"] == dict(CLUSTERING_DEFAULTS)

    def test_null_section_and_null_keys_fall_back_per_key(self, tmp_path: Path) -> None:
        cfg = load_config(
            self._write(tmp_path, {"clustering": {"k_max": None}})
        )
        assert cfg["clustering"] == dict(CLUSTERING_DEFAULTS)

    def test_partial_section_merges_over_defaults(self, tmp_path: Path) -> None:
        cfg = load_config(self._write(tmp_path, {"clustering": {"k_max": 3}}))
        assert cfg["clustering"] == dict(CLUSTERING_DEFAULTS, k_max=3)

    def test_full_custom_section_passes_through(self, tmp_path: Path) -> None:
        custom = {"min_clusterable": 8, "k_max": 4, "silhouette_threshold": 0.25,
                  "max_vocab": 300, "seed": 7}
        cfg = load_config(self._write(tmp_path, {"clustering": custom}))
        assert cfg["clustering"] == custom

    def test_existing_keys_untouched_by_extension(self, tmp_path: Path) -> None:
        payload = {
            "platform_scope": "windows",
            "detection_confidence_threshold": 0.55,
            "enabled_log_sources": {"evtx": True, "cef": False},
        }
        cfg = load_config(self._write(tmp_path, payload))
        assert cfg["platform_scope"] == "windows"
        assert cfg["detection_confidence_threshold"] == 0.55
        assert cfg["enabled_log_sources"]["cef"] is False

    @pytest.mark.parametrize(
        "section",
        [
            {"min_clusterable": -1},           # below minimum 1
            {"min_clusterable": "four"},       # wrong type
            {"min_clusterable": True},         # bool rejected despite int subclass
            {"k_max": 0},                      # below minimum 2
            {"silhouette_threshold": 1.5},     # outside [-1.0, 1.0]
            {"max_vocab": 0},                  # below minimum 1
            {"seed": "forty-two"},             # wrong type
            {"seed": -1},                      # outside [0, 2**32-1]
            "not-a-mapping",                   # whole section wrong type
        ],
    )
    def test_invalid_values_raise_valueerror(
        self, tmp_path: Path, section: Any
    ) -> None:
        with pytest.raises(ValueError):
            load_config(self._write(tmp_path, {"clustering": section}))

    def test_negative_silhouette_within_score_domain_is_accepted(
        self, tmp_path: Path
    ) -> None:
        # the silhouette coefficient domain is [-1, 1]; the config loader
        # accepts the full domain (the stricter (>0) gate lives in
        # ClusteringParams.from_config, tested in the clustering section).
        cfg = load_config(
            self._write(tmp_path, {"clustering": {"silhouette_threshold": -0.1}})
        )
        assert cfg["clustering"]["silhouette_threshold"] == -0.1

    def test_repo_config_yaml_loads_with_extension(self) -> None:
        """The shipped config.yaml (no clustering section yet) still loads."""
        cfg = load_config(str(REPO_CONFIG_YAML))
        assert cfg["clustering"] == dict(CLUSTERING_DEFAULTS)


# ---------------------------------------------------------------------------
# (G) loader data fixes
# ---------------------------------------------------------------------------


def _stix_pattern(obj_id: str = "attack-pattern--fix1",
                  attack_id: str = "T1234",
                  *,
                  phases: Sequence[dict[str, str]] = (),
                  revoked: bool = False,
                  deprecated: bool = False,
                  sub: bool = False) -> dict[str, Any]:
    return {
        "type": "attack-pattern",
        "id": obj_id,
        "name": "Fix Probe",
        "external_references": [
            {"external_id": attack_id, "source_name": "mitre-attack"}
        ],
        "kill_chain_phases": list(phases),
        "x_mitre_platforms": ["Windows"],
        "x_mitre_is_subtechnique": sub,
        "revoked": revoked,
        "x_mitre_deprecated": deprecated,
    }


class TestLoaderDataFixes:
    """Deprecated-as-revoked flagging plus v19 tactic-phase aliasing."""

    def test_fresh_load_report_unknown_phase_count_defaults_zero(self) -> None:
        assert LoadReport().unknown_phase_count == 0

    def test_deprecated_treated_as_revoked(self) -> None:
        rows = _technique_rows([_stix_pattern(deprecated=True)], LoadReport())
        assert len(rows) == 1
        assert rows[0]["revoked"] is True

    def test_plain_revoked_stays_revoked_and_clean_stays_active(self) -> None:
        rows = _technique_rows(
            [
                _stix_pattern(obj_id="attack-pattern--fix-r", revoked=True),
                _stix_pattern(obj_id="attack-pattern--fix-a", attack_id="T1235"),
            ],
            LoadReport(),
        )
        flags = {row["attack_id"]: row["revoked"] for row in rows}
        assert flags == {"T1234": True, "T1235": False}

    @pytest.mark.parametrize("phase", ["stealth", "defense-impairment"])
    def test_v19_phase_aliases_map_to_defense_evasion(self, phase: str) -> None:
        rows = _technique_rows(
            [_stix_pattern(phases=[
                {"kill_chain_name": "mitre-attack", "phase_name": phase}
            ])],
            LoadReport(),
        )
        assert rows[0]["tactics"] == ["defense-evasion"]

    def test_alias_applied_before_allowlist_keeps_other_tactics(self) -> None:
        rows = _technique_rows(
            [_stix_pattern(phases=[
                {"kill_chain_name": "mitre-attack", "phase_name": "stealth"},
                {"kill_chain_name": "mitre-attack",
                 "phase_name": "initial-access"},
            ])],
            LoadReport(),
        )
        assert sorted(rows[0]["tactics"]) == [
            "defense-evasion",
            "initial-access",
        ]

    def test_unknown_phase_excluded_but_counted(self) -> None:
        report = LoadReport()
        rows = _technique_rows(
            [_stix_pattern(phases=[
                {"kill_chain_name": "mitre-attack", "phase_name": "stealth"},
                {"kill_chain_name": "mitre-attack",
                 "phase_name": "totally-bogus"},
            ])],
            report,
        )
        assert rows[0]["tactics"] == ["defense-evasion"]
        assert report.unknown_phase_count == 1

    def test_non_mitre_kill_chain_never_counts_as_unknown(self) -> None:
        report = LoadReport()
        _technique_rows(
            [_stix_pattern(phases=[
                {"kill_chain_name": "mitre-mobile-attack",
                 "phase_name": "whatever"},
            ])],
            report,
        )
        assert report.unknown_phase_count == 0

    def test_duplicate_aliases_dedupe_to_one_slug(self) -> None:
        report = LoadReport()
        rows = _technique_rows(
            [_stix_pattern(phases=[
                {"kill_chain_name": "mitre-attack", "phase_name": "stealth"},
                {"kill_chain_name": "mitre-attack",
                 "phase_name": "defense-impairment"},
            ])],
            report,
        )
        assert rows[0]["tactics"] == ["defense-evasion"]
        assert report.unknown_phase_count == 0

    def test_subtechnique_parent_derivation_byte_compatible(self) -> None:
        rows = _technique_rows(
            [_stix_pattern(attack_id="T1234.001", sub=True)], LoadReport()
        )
        row = rows[0]
        assert row["is_subtechnique"] is True
        assert row["parent_attack_id"] == "T1234"


# ---------------------------------------------------------------------------
# static scoring helpers (contract D building blocks)
# ---------------------------------------------------------------------------


class TestStaticScoringHelpers:
    """Shape-derived tiers and the 0.95 cap behind populate/gap math."""

    def test_tier_precedence_heuristic_over_ext_keys(self) -> None:
        heuristic_with_ext = make_rule(
            "Z001", "evtx", 0.45, "T0000", "execution", ext="foo",
            match_type="heuristic",
        )
        assert coverage_analyzer.rule_tier_multiplier(heuristic_with_ext) == 0.40

    def test_ext_action_only_multipliers(self) -> None:
        ext_rule = make_rule("Z002", "evtx", 0.70, "T0000", "execution",
                             ext="foo")
        action_rule = make_rule("Z003", "evtx", 0.70, "T0000", "execution",
                                action=r"^deny$")
        assert coverage_analyzer.rule_tier_multiplier(ext_rule) == 1.00
        assert coverage_analyzer.rule_tier_multiplier(action_rule) == 0.85

    def test_cap_at_point_nine_five(self) -> None:
        hot = make_rule("Z004", "evtx", 1.00, "T0000", "execution", ext="foo")
        assert coverage_analyzer.static_rule_score(hot) == 0.95


# ---------------------------------------------------------------------------
# (C)/(B)/(D)/(E) synthetic-universe populate + analyzer semantics
# ---------------------------------------------------------------------------


class TestPopulateSemanticsSynthetic:
    """Surrogate-PK-safe idempotency, tier math, skips, stale deletion."""

    def test_populate_report_shape_and_initial_inserts(self, synth_env) -> None:
        report: Any = synth_env["report"]
        assert isinstance(report, coverage_analyzer.PopulateReport)
        # desired pairs: (T1000,evtx)(T1001,evtx)(T1001,json)(T1004,zeek)
        assert report.rows_upserted == 4
        assert report.rows_inserted == 4
        assert report.rows_updated == 0
        assert report.rows_deleted == 0
        assert "T1003" in report.skipped_revoked
        assert "T9999" in report.skipped_orphan
        # 1 revoked skip + 1 orphan skip + 1 unknown-format rule
        assert report.warnings == 3
        assert_frozen_hashable(report)

    def test_unknown_source_format_skipped_not_persisted(self, synth_env) -> None:
        pairs = coverage_pairs_by_format(synth_env["session"])
        assert not any(fmt == "arcsight" for _, fmt in pairs)

    def test_disabled_formats_produce_no_rows(self, synth_env) -> None:
        pairs = coverage_pairs_by_format(synth_env["session"])
        for _, fmt in pairs:
            assert fmt not in DEFAULT_DISABLED_FORMATS

    def test_static_tier_math_cap_and_boundary(self, synth_env) -> None:
        pairs = coverage_pairs_by_format(synth_env["session"])
        # X001 base 1.00 ext-rule -> capped at 0.95 (contract D cap).
        conf, det = pairs[("T1000", "evtx")]
        assert conf == pytest.approx(0.95, abs=1e-9) and det is True
        # same-source max: tier-1 0.60 beats tier-2 0.51 for (T1001,evtx);
        # 0.60 == threshold counts as detectable (inclusive boundary).
        conf, det = pairs[("T1001", "evtx")]
        assert conf == pytest.approx(0.60, abs=1e-9)
        assert det is True
        # cross-source rows kept separately: heuristic json row exists, low.
        conf, det = pairs[("T1001", "json")]
        assert conf == pytest.approx(0.36, abs=1e-9) and det is False

    def test_second_run_is_a_noop(self, synth_env) -> None:
        session, cfg, rules = (
            synth_env["session"], synth_env["cfg"], synth_env["rules"]
        )
        before = coverage_pairs_by_format(session)
        report = coverage_analyzer.populate_technique_coverage(
            session, rules, cfg
        )
        session.commit()
        assert report.rows_inserted == 0
        assert report.rows_updated == 0
        assert report.rows_deleted == 0
        # nothing was written this run => upserted (inserted+updated) is 0
        assert report.rows_upserted == 0
        assert coverage_pairs_by_format(session) == before

    def test_rule_change_updates_row_in_place(self, synth_env) -> None:
        session, cfg = synth_env["session"], synth_env["cfg"]
        bumped = [
            r if r.mapping_id != "X003"
            else make_rule("X003", "evtx", 0.75, "T1001", "persistence",
                           ext="cmdline")
            for r in synth_env["rules"]
        ]
        report = coverage_analyzer.populate_technique_coverage(
            session, bumped, cfg
        )
        session.commit()
        assert report.rows_inserted == 0
        assert report.rows_updated >= 1
        assert report.rows_deleted == 0
        pairs = coverage_pairs_by_format(session)
        assert pairs[("T1001", "evtx")][0] == pytest.approx(0.75, abs=1e-9)

    def test_disable_all_sources_deletes_everything_empty_state(
        self, synth_env
    ) -> None:
        session = synth_env["session"]
        empty_cfg = default_cfg(
            enabled_log_sources={fmt: False for fmt in KNOWN_FORMATS}
        )
        report = coverage_analyzer.populate_technique_coverage(
            session, synth_env["rules"], empty_cfg
        )
        session.commit()
        assert report.rows_deleted == 4  # every previously written pair
        assert report.rows_inserted == 0
        assert coverage_pairs_by_format(session) == {}

        rows = coverage_analyzer.load_coverage_rows(session, empty_cfg)
        tactic_rows = coverage_analyzer.coverage_by_tactic(rows)
        assert tuple(tc.tactic for tc in tactic_rows) == CANONICAL_TACTICS
        expected_totals = {
            "execution": 2, "persistence": 1, "discovery": 1, "impact": 1,
            "command-and-control": 1, "exfiltration": 1,
            "resource-development": 1,
        }
        for tc in tactic_rows:
            assert tc.total == expected_totals.get(tc.tactic, 0), tc.tactic
            assert tc.detectable == 0
            assert tc.pct == 0.0
        gaps = coverage_analyzer.calculate_coverage_gaps(
            rows, synth_env["rules"], empty_cfg
        )
        # every in-scope alive (technique, tactic) row is now a gap;
        # T1001 spans two tactics -> 8 gap rows, none raises.
        assert len(gaps) == 8
        assert_frozen_hashable(gaps)


class TestCoverageAndGapSemanticsSynthetic:
    """Platform scoping, tactic denominators, ordering, honest closable_by."""

    def test_platform_scope_element_wise_case_insensitive(self, synth_env) -> None:
        by_id: dict[str, list[Any]] = {}
        for row in coverage_analyzer.load_coverage_rows(
            synth_env["session"], synth_env["cfg"]
        ):
            by_id.setdefault(row.attack_id, []).append(row)
        # exact element-wise equality, case-insensitive (contract B):
        # 'windows'.lower() must match platform 'Windows' exactly.
        assert all(not row.scope_hit for row in by_id["T1002"])  # Linux only
        assert all(row.scope_hit for row in by_id["T1001"])  # Windows+Linux
        assert all(row.scope_hit for row in by_id["T1008"])  # Windows+macOS
        assert "T1003" not in by_id, "revoked technique must be excluded"

    def test_coverage_by_tactic_canonical_order_and_math(self, synth_env) -> None:
        result = coverage_analyzer.coverage_by_tactic(
            coverage_analyzer.load_coverage_rows(
                synth_env["session"], synth_env["cfg"]
            )
        )
        assert isinstance(result, tuple)
        assert tuple(tc.tactic for tc in result) == CANONICAL_TACTICS
        by_tactic = {tc.tactic: tc for tc in result}
        expected_totals = {
            "execution": 2,      # T1000 + T1001 (multi-tactic once per tactic)
            "persistence": 1,    # T1001 only; revoked T1003 excluded
            "discovery": 1,
            "impact": 1,
            "command-and-control": 1,
            "exfiltration": 1,
            "resource-development": 1,   # T1008 windows+macOS counts
        }
        for tactic, total in expected_totals.items():
            assert by_tactic[tactic].total == total, tactic
        assert by_tactic["reconnaissance"].total == 0  # zero buckets emitted
        assert by_tactic["execution"].detectable == 2
        assert by_tactic["execution"].pct == pytest.approx(round(2 / 2, 4))
        assert by_tactic["command-and-control"].detectable == 0
        assert by_tactic["command-and-control"].pct == 0.0
        for tc in result:
            assert_frozen_hashable(tc)

    def test_gaps_sorted_honest_closable_by(self, synth_env) -> None:
        gaps = coverage_analyzer.calculate_coverage_gaps(
            coverage_analyzer.load_coverage_rows(
                synth_env["session"], synth_env["cfg"]
            ),
            synth_env["rules"],
            synth_env["cfg"],
        )
        assert isinstance(gaps, tuple)
        # gaps sort by canonical tactic position, then best asc, then id;
        # comparing raw slugs alphabetically would be a different order
        # (e.g. credential-access precedes defense-evasion canonically but
        # follows it alphabetically).
        keys = [
            (CANONICAL_TACTICS.index(g.tactic), float(g.best_confidence))
            for g in gaps
        ]
        assert keys == sorted(keys), "gaps sort by (canonical tactic, best asc)"

        by_id = {g.technique_attack_id: g for g in gaps}
        # honest positive: mapping on a disabled source whose statically
        # projected score clears the bar -> closable.
        t1005 = by_id["T1005"]
        assert t1005.tactic == "command-and-control"
        assert t1005.best_confidence == pytest.approx(0.0, abs=1e-9)
        assert t1005.closable_by == ("cef",)
        # honest negative: leef mapping exists but projects 0.425 < 0.6 ->
        # naive any-mapping logic would promise leef closes it; must not.
        t1006 = by_id["T1006"]
        assert t1006.closable_by == ()
        # out-of-scope and revoked techniques never become gaps
        assert "T1002" not in by_id and "T1003" not in by_id
        assert_frozen_hashable(gaps)

    def test_enabling_cef_closes_the_c2_gap(self, synth_env) -> None:
        session = synth_env["session"]
        cef_on = default_cfg(enabled_log_sources={"cef": True})
        report = coverage_analyzer.populate_technique_coverage(
            session, synth_env["rules"], cef_on
        )
        session.commit()
        assert report.rows_inserted >= 1  # (T1005, cef) appears at 0.85
        gaps = coverage_analyzer.calculate_coverage_gaps(
            coverage_analyzer.load_coverage_rows(session, cef_on),
            synth_env["rules"],
            cef_on,
        )
        assert "T1005" not in {g.technique_attack_id for g in gaps}

        # disabling cef again while enabling leef flips closable_by honestly
        leef_on = default_cfg(enabled_log_sources={"cef": False, "leef": True})
        coverage_analyzer.populate_technique_coverage(
            session, synth_env["rules"], leef_on
        )
        session.commit()
        gaps = coverage_analyzer.calculate_coverage_gaps(
            coverage_analyzer.load_coverage_rows(session, leef_on),
            synth_env["rules"],
            leef_on,
        )
        by_id = {g.technique_attack_id: g for g in gaps}
        assert by_id["T1006"].best_confidence == pytest.approx(0.425, abs=1e-9)
        assert by_id["T1006"].closable_by == ()  # its only source is enabled


# ---------------------------------------------------------------------------
# (A)/(C)/(D)/(E)/(I)/(N) golden real-data integration
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not STIX_CACHE.is_file(),
    reason=(
        "data/attack_stix/enterprise-attack.json is gitignored (large, "
        "re-downloadable) and therefore absent from a fresh clone/CI; run the "
        "ATT&CK ingest (scripts/populate_db.py) to enable the golden real-data "
        "tests. Same guard pattern as tests/test_performance.py."
    ),
)
class TestGoldenRealDataIntegration:
    """Real CSV x real cache universe x repo config -> Wave-1 goldens."""

    def test_real_mappings_load_cleanly(self) -> None:
        assert len(load_mappings(str(MAPPINGS_CSV))) == 83

    def test_populate_report_golden_skips(self, golden_env) -> None:
        report: Any = golden_env["report"]
        assert report.rows_deleted == 0
        assert report.rows_updated == 0
        assert report.rows_inserted == report.rows_upserted
        assert report.rows_upserted > 0
        # Owner retargeted every formerly-revoked target (M014/M033 ->
        # T1685.005, M016 -> T1685.002, M044/M061 -> T1685), so no CSV row
        # may land on a revoked/deprecated technique any more.
        assert report.skipped_revoked == (), (
            f"unexpected revoked skips: {report.skipped_revoked}"
        )
        assert set(report.skipped_orphan) == set(), "all CSV ids resolvable"
        assert report.warnings == len(report.skipped_revoked)
        assert_frozen_hashable(report)

    def test_golden_populate_rows_exact(self, golden_env) -> None:
        pairs = coverage_pairs_by_format(golden_env["session"])
        for attack_id, fmt, conf, detectable in GOLDEN_POPULATE_ROWS:
            key = (attack_id, fmt)
            assert key in pairs, f"missing golden pair {key}"
            got_conf, got_det = pairs[key]
            assert got_conf == pytest.approx(conf, abs=1e-9), key
            assert got_det is detectable, key
        for _, fmt in pairs:
            assert fmt not in DEFAULT_DISABLED_FORMATS
        # no rows for disabled-source-only techniques
        assert ("T1190", "nginx") not in pairs
        assert ("T1110.001", "leef") not in pairs
        assert ("T1136", "cef") not in pairs
        # revoked targets have no rows on any format
        for revoked_id in GOLDEN_REVOKED_TARGETS:
            assert not any(a == revoked_id for a, _ in pairs)

    def test_populate_idempotent_over_real_csv(self, golden_env) -> None:
        session, cfg, rules = (
            golden_env["session"], golden_env["cfg"], golden_env["rules"]
        )
        before = coverage_pairs_by_format(session)
        report = coverage_analyzer.populate_technique_coverage(
            session, rules, cfg
        )
        session.commit()
        assert report.rows_inserted == 0
        assert report.rows_updated == 0
        assert report.rows_deleted == 0
        assert report.rows_upserted == 0
        assert coverage_pairs_by_format(session) == before

    def test_execution_golden_slice(self, golden_env) -> None:
        rows = coverage_analyzer.load_coverage_rows(
            golden_env["session"], golden_env["cfg"]
        )
        exec_rows = [r for r in rows if r.tactic == "execution"]
        assert exec_rows, "execution bucket must be populated"
        # denominator pin lives in test_execution_denominator_pinned_at_46;
        # here we pin the detectable set and their best confidences exactly.
        detectable = {
            r.attack_id: float(r.best_confidence)
            for r in exec_rows
            if r.is_detectable and r.scope_hit
        }
        assert set(detectable) == set(GOLDEN_EXECUTION_DETECTABLE_IDS)
        assert detectable == GOLDEN_EXECUTION_DETECTABLE_CONFIDENCES

    def test_execution_denominator_pinned_at_46(self, golden_env) -> None:
        result = coverage_analyzer.coverage_by_tactic(
            coverage_analyzer.load_coverage_rows(
                golden_env["session"], golden_env["cfg"]
            )
        )
        execution = next(tc for tc in result if tc.tactic == "execution")
        assert execution.total == GOLDEN_EXECUTION_TOTAL
        assert execution.detectable == len(GOLDEN_EXECUTION_DETECTABLE_IDS)
        assert execution.pct == pytest.approx(
            round(len(GOLDEN_EXECUTION_DETECTABLE_IDS) / GOLDEN_EXECUTION_TOTAL, 4)
        )

    def test_unmapped_inscope_techniques_present_with_zero(
        self, golden_env
    ) -> None:
        rows = coverage_analyzer.load_coverage_rows(
            golden_env["session"], golden_env["cfg"]
        )
        t1059 = [r for r in rows if r.attack_id == "T1059"]
        assert t1059, "unmapped-but-in-scope techniques must still emit rows"
        assert all(float(r.best_confidence) == 0.0 for r in t1059)
        assert all(not r.is_detectable for r in t1059)

    def test_tactic_totals_match_independent_universe_recount(
        self, golden_env
    ) -> None:
        cfg = golden_env["cfg"]
        rows = coverage_analyzer.load_coverage_rows(golden_env["session"], cfg)
        result = coverage_analyzer.coverage_by_tactic(rows)

        scope = str(cfg["platform_scope"]).lower()
        recount: dict[str, int] = {t: 0 for t in CANONICAL_TACTICS}
        for technique in golden_env["session"].query(Technique).all():
            if technique.revoked:
                continue
            platforms = {str(p).lower() for p in (technique.platforms or [])}
            if scope != "all" and scope not in platforms:
                continue
            for tactic in technique.tactics or []:
                if tactic in recount:
                    recount[tactic] += 1

        assert tuple(tc.tactic for tc in result) == CANONICAL_TACTICS
        assert len(result) == 14, "all 14 Enterprise tactics always emitted"
        for tc in result:
            assert tc.total == recount[tc.tactic], tc.tactic
            if tc.total == 0:
                assert tc.pct == 0.0
            else:
                assert tc.pct == pytest.approx(
                    round(tc.detectable / tc.total, 4)
                ), tc.tactic

    def test_recon_and_resource_development_structurally_zero(
        self, golden_env
    ) -> None:
        """Explained-gap note (contract N): every reconnaissance and
        resource-development technique in Enterprise ATT&CK carries ONLY the
        ``PRE`` platform, so under ``platform_scope: windows`` both tactics
        fall outside the denominator entirely -- their buckets are structurally
        zeroed before the (also real) mapping-supply gap of 0/83 CSV rules
        ever comes into play."""
        result = coverage_analyzer.coverage_by_tactic(
            coverage_analyzer.load_coverage_rows(
                golden_env["session"], golden_env["cfg"]
            )
        )
        by_tactic = {tc.tactic: tc for tc in result}
        universe = cached_universe(str(STIX_CACHE))
        for tactic in ("reconnaissance", "resource-development"):
            tagged = [r for r in universe if tactic in r["tactics"]]
            assert tagged, f"{tactic} exists in the bundle"
            assert all(
                p.upper() == "PRE" for r in tagged for p in r["platforms"]
            ), f"every {tactic} technique is PRE-only by construction"
            assert by_tactic[tactic].total == 0
            assert by_tactic[tactic].detectable == 0
            assert by_tactic[tactic].pct == 0.0

    def test_gaps_golden_t1190_closable_by_nginx(self, golden_env) -> None:
        cfg = golden_env["cfg"]
        gaps = coverage_analyzer.calculate_coverage_gaps(
            coverage_analyzer.load_coverage_rows(golden_env["session"], cfg),
            golden_env["rules"],
            cfg,
        )
        by_id = {g.technique_attack_id: g for g in gaps}
        # measured Wave-1 example (contract E)
        t1190 = by_id["T1190"]
        assert t1190.tactic == "initial-access"
        assert t1190.best_confidence == pytest.approx(0.0, abs=1e-9)
        assert t1190.closable_by == ("nginx",)
        # honest negative: T1136 has a disabled cef mapping but its static
        # projection 0.45x0.85 stays below the bar -> nothing promised.
        assert by_id["T1136"].closable_by == ()
        # revoked techniques never appear
        for revoked_id in GOLDEN_REVOKED_TARGETS:
            assert revoked_id not in by_id
        # canonical (tactic position, best asc, id) total ordering
        keys = [
            (CANONICAL_TACTICS.index(g.tactic), float(g.best_confidence))
            for g in gaps
        ]
        assert keys == sorted(keys)
        assert_frozen_hashable(gaps)

    def test_toggle_zeek_flips_t1110_001_between_detected_and_gap(
        self, tmp_path: Path
    ) -> None:
        """Demo beat end-to-end on a fresh env copy (mutation isolated)."""
        universe = cached_universe(str(STIX_CACHE))
        engine, session = build_db(tmp_path, "toggle.db", universe)
        try:
            zeek_off = default_cfg(enabled_log_sources={"zeek": False})
            rules = load_mappings(str(MAPPINGS_CSV))
            coverage_analyzer.populate_technique_coverage(
                session, rules, zeek_off
            )
            session.commit()
            gaps = coverage_analyzer.calculate_coverage_gaps(
                coverage_analyzer.load_coverage_rows(session, zeek_off),
                rules,
                zeek_off,
            )
            by_id = {g.technique_attack_id: g for g in gaps}
            t1110_001 = by_id["T1110.001"]
            assert t1110_001.best_confidence == pytest.approx(0.51, abs=1e-9)
            assert t1110_001.closable_by == ("zeek",)  # 0.765 >= 0.6 projected

            full_cfg = default_cfg()
            coverage_analyzer.populate_technique_coverage(
                session, rules, full_cfg
            )
            session.commit()
            rows = coverage_analyzer.load_coverage_rows(session, full_cfg)
            t1110_001_rows = [
                r for r in rows if r.attack_id == "T1110.001"
            ]
            assert t1110_001_rows
            assert all(
                float(r.best_confidence) == pytest.approx(0.765, abs=1e-9)
                for r in t1110_001_rows
            )
            assert all(r.is_detectable for r in t1110_001_rows)
            gaps_after = coverage_analyzer.calculate_coverage_gaps(
                rows, rules, full_cfg
            )
            assert "T1110.001" not in {
                g.technique_attack_id for g in gaps_after
            }
        finally:
            session.close()
            engine.dispose()

    def test_public_return_types_are_frozen_dataclasses(
        self, golden_env
    ) -> None:
        cfg = golden_env["cfg"]
        rows = coverage_analyzer.load_coverage_rows(golden_env["session"], cfg)
        assert rows
        assert dataclasses.is_dataclass(rows[0])
        assert rows[0].__class__.__dataclass_params__.frozen is True
        tactic_rows = coverage_analyzer.coverage_by_tactic(rows)
        assert tactic_rows[0].__class__.__dataclass_params__.frozen is True
        gaps = coverage_analyzer.calculate_coverage_gaps(
            rows, golden_env["rules"], cfg
        )
        assert gaps
        assert gaps[0].__class__.__dataclass_params__.frozen is True
        assert_frozen_hashable((rows[:5], tactic_rows, gaps))


# ---------------------------------------------------------------------------
# (F) gap clustering
# ---------------------------------------------------------------------------


def _theme_items(prefix: str, tactic: str, words: str, count: int) -> list[GapItem]:
    return [
        make_gap_item(
            f"{prefix}{i:02d}",
            tactic,
            description=f"{words} behaviour pattern variant {i}",
        )
        for i in range(count)
    ]


class TestGapClusteringContract:
    """Deterministic KMeans policy: small-n fallback, silhouette gate."""

    def test_empty_input_returns_empty_tuple(self) -> None:
        assert cluster_gaps([], ClusteringParams()) == ()

    def test_default_params_none_equivalent(self) -> None:
        items = _theme_items("T91", "impact", "disk wipe sabotage", 2)
        assert repr(cluster_gaps(items, None)) == repr(
            cluster_gaps(items, ClusteringParams())
        )

    @pytest.mark.parametrize("n", [1, 2, 3])
    def test_below_min_clusterable_single_cluster_no_kmeans(self, n: int) -> None:
        items = [make_gap_item(f"T{n}00{i}", "discovery") for i in range(n)]
        result = cluster_gaps(items, ClusteringParams())
        assert len(result) == 1
        cluster = result[0]
        assert cluster.size == n
        assert set(cluster.technique_ids) == {
            i.technique_attack_id for i in items
        }

    def test_two_disjoint_themes_split_into_clusters(self) -> None:
        items = _theme_items(
            "T20", "credential-access",
            "kerberos ntlm credential theft ticket forging domain controller",
            4,
        ) + _theme_items(
            "T30", "exfiltration",
            "http beacon upload encrypted channel dns tunneling outbound flow",
            4,
        )
        result = cluster_gaps(items, ClusteringParams())
        assert len(result) >= 2, "well-separated themes must split"
        members = [tid for c in result for tid in c.technique_ids]
        assert sorted(members) == sorted(i.technique_attack_id for i in items)
        assert len(members) == len(set(members)), "clusters must be disjoint"
        labels_joined = " ".join(c.label.lower() for c in result)
        assert "credential-access" in labels_joined
        assert "exfiltration" in labels_joined
        for cluster in result:
            assert cluster.size == len(cluster.technique_ids)
            assert cluster.size >= 2
            assert cluster.label, "labels must be non-empty"
            # contract F summary shape: '<n> undetected techniques ...'
            assert cluster.summary.startswith(
                f"{cluster.size} undetected techniques"
            )
            assert cluster.summary.strip().endswith(".")

    def test_gate_rejection_forces_single_cluster(self) -> None:
        """An unreachable silhouette bar deterministically exercises the
        acceptance-gate rejection branch -> conservative single cluster."""
        items = _theme_items(
            "T20", "credential-access", "kerberos ticket forging", 4
        ) + _theme_items("T30", "exfiltration", "dns tunneling upload", 4)
        strict = ClusteringParams(silhouette_threshold=0.999999)
        result = cluster_gaps(items, strict)
        assert len(result) == 1
        assert result[0].size == 8

    def test_identical_vectors_nan_silhouette_falls_back(self) -> None:
        # byte-identical feature vectors (same name AND description) make
        # every pairwise distance equal -> NaN/degenerate silhouette ->
        # the policy must fall back to ONE cluster, never crash.
        items = [
            GapItem(
                technique_attack_id=f"T40{i:02d}",
                name="Identical disk encryption sabotage technique",
                tactic="impact",
                description="identical disk encryption sabotage payload "
                            "behaviour pattern",
            )
            for i in range(10)
        ]
        result = cluster_gaps(items, ClusteringParams())
        assert len(result) == 1
        assert result[0].size == 10
        assert set(result[0].technique_ids) == {
            i.technique_attack_id for i in items
        }

    def test_determinism_byte_identical_outputs(self) -> None:
        items = _theme_items("T5", "collection", "email archive scrape", 3) \
            + _theme_items("T6", "collection", "browser history theft", 3)
        first = cluster_gaps(items, ClusteringParams())
        second = cluster_gaps(items, ClusteringParams())
        assert repr(first) == repr(second)
        members = [tid for c in first for tid in c.technique_ids]
        assert sorted(members) == sorted(i.technique_attack_id for i in items)

    def test_cluster_shapes_frozen_and_hashable(self) -> None:
        items = [
            make_gap_item("T6001", "execution", "wmi exec spawn"),
            make_gap_item("T6002", "execution", "wmic process launch"),
        ]
        result = cluster_gaps(items, ClusteringParams())
        for cluster in result:
            assert_frozen_hashable(cluster)

    def test_gap_item_is_frozen_dataclass(self) -> None:
        item = make_gap_item("T7001", "discovery", "probe")
        assert dataclasses.is_dataclass(item)
        with pytest.raises(dataclasses.FrozenInstanceError):
            item.tactic = "impact"  # type: ignore[misc]

    def test_params_typeerror_for_plain_dict(self) -> None:
        items = [make_gap_item("T8001", "impact", "wipe")]
        with pytest.raises(TypeError):
            cluster_gaps(items, {"seed": 42})  # type: ignore[arg-type]

    def test_clustering_params_from_config_defaults_and_validation(self) -> None:
        params = ClusteringParams.from_config(None)
        assert params == ClusteringParams(**CLUSTERING_DEFAULTS)
        merged = ClusteringParams.from_config({"k_max": 3})
        assert merged.k_max == 3
        assert merged.min_clusterable == CLUSTERING_DEFAULTS["min_clusterable"]
        for bad in (
            {"min_clusterable": 0},
            {"k_max": 1},
            {"silhouette_threshold": -0.1},  # from_config demands (>0, <=1]
            {"max_vocab": 0},
            {"seed": -5},
            {"seed": "x"},
        ):
            with pytest.raises(ValueError):
                ClusteringParams.from_config(bad)

    def test_conservative_outcome_matches_wave1_expectation(self) -> None:
        """Homogeneous large sets refuse to split (Wave-1 finding).

        The real ~449-gap set measures max mean silhouette ~0.168 < 0.20
        and the correct behaviour is ONE cluster. The deterministic
        analogue here is the identical-vector construction (see
        test_identical_vectors_nan_silhouette_falls_back); this test adds
        the structural invariants that must hold whatever the sweep decides
        for a weakly-separated homogeneous set.
        """
        words = ["process", "service", "registry", "script", "token",
                 "memory", "network", "account"]
        items = [
            make_gap_item(
                f"T8{i:03d}",
                "defense-evasion",
                " ".join(words[i % len(words):] + words[: i % len(words)]),
            )
            for i in range(24)
        ]
        result = cluster_gaps(items, ClusteringParams())
        members = [tid for c in result for tid in c.technique_ids]
        assert sorted(members) == sorted(i.technique_attack_id for i in items)
        assert len(members) == len(set(members))
        for cluster in result:
            assert cluster.size >= 2 or len(result) == 1
