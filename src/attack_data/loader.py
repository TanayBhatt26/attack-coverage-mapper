"""Idempotent ATT&CK Enterprise loader.

Load order is FK-safe: techniques -> detection strategies -> analytics ->
groups -> group-technique relations -> meta. Every write is a `merge`
(upsert by primary key), so re-runs are no-ops except loaded_at.

Two data fixes are applied while loading (row counts stay unchanged; only
flags/tags differ):

* Deprecation: STIX marks retired-but-not-revoked objects with
  ``x_mitre_deprecated=true``. The schema has no dedicated deprecation
  column, so deprecated techniques are folded onto the existing
  ``revoked`` flag/column (kept rows, ``Technique.revoked`` set True).
  Consumers that filter on ``revoked`` for "alive" therefore exclude
  both kinds automatically.
* ATT&CK v19 tactic rename: the bundle carries kill-chain phases
  ``stealth`` and ``defense-impairment`` where older releases had
  ``defense-evasion``. Both are aliased to ``defense-evasion``
  *before* the enterprise-tactic allowlist so affected techniques keep
  a tactic tag instead of collapsing to ``tactics=[]``. Mitre-attack
  phases that remain unmapped after aliasing stay out of ``tactics``
  but are tallied in ``LoadReport.unknown_phase_count``.
"""
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy.orm import Session

from database.models import (
    Analytic,
    AttackMeta,
    AptGroup,
    AptTechnique,
    DetectionStrategy,
    Technique,
    utcnow,
)

from .client import DEFAULT_CACHE, SnapshotInfo, load_or_fetch, stix_external_id

logger = logging.getLogger(__name__)

# Tactics we keep from kill-chain phases on techniques (Enterprise set).
ENTERPRISE_TACTICS = {
    "reconnaissance", "resource-development", "initial-access",
    "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
}

# ATT&CK v19 tactic renames -> canonical slug, applied BEFORE the
# ENTERPRISE_TACTICS allowlist. The cached bundle uses 'stealth' (212 phase
# entries) and 'defense-impairment' (56) where older releases had
# 'defense-evasion'; without this map those techniques load with tactics=[]
# and vanish from every per-tactic view.
PHASE_ALIASES = {
    "stealth": "defense-evasion",
    "defense-impairment": "defense-evasion",
}


@dataclass
class LoadReport:
    counts: dict = field(default_factory=dict)
    snapshot: SnapshotInfo | None = None
    warnings: int = 0
    # mitre-attack kill-chain phases dropped by the tactic allowlist even
    # after PHASE_ALIASES mapping. They stay OUT of techniques.tactics;
    # this counter only records how many entries were discarded.
    unknown_phase_count: int = 0


def _canonical_tactics(raw_phases: list, report: LoadReport) -> list[str]:
    """Normalize mitre-attack kill-chain phases into canonical tactic slugs.

    PHASE_ALIASES runs *before* the ENTERPRISE_TACTICS allowlist so renamed
    phases (ATT&CK v19) land on their canonical tactic. Phases that remain
    unmapped after aliasing are kept out of the result and tallied in
    ``report.unknown_phase_count``. Output is order-preserving and
    duplicate-free (both aliases map to the same slug).
    """
    out: list[str] = []
    for phase in raw_phases:
        canonical = PHASE_ALIASES.get(phase, phase)
        if canonical not in ENTERPRISE_TACTICS:
            report.unknown_phase_count += 1
            continue
        if canonical not in out:
            out.append(canonical)
    return out


def _technique_rows(data: list[dict], report: LoadReport) -> list[dict]:
    rows: dict[str, dict] = {}
    detects: dict[str, list[str]] = {}  # attack_pattern stix_id -> [strategy ids]
    for obj in data:
        t = obj.get("type")
        if t == "attack-pattern":
            attack_id = stix_external_id(obj)
            if not attack_id:
                report.warnings += 1
                continue
            raw_phases = [
                kc.get("phase_name")
                for kc in obj.get("kill_chain_phases") or []
                if kc.get("kill_chain_name") == "mitre-attack"
            ]
            parent = None
            is_sub = bool(obj.get("x_mitre_is_subtechnique", False))
            if is_sub and "." in attack_id:
                parent = attack_id.rsplit(".", 1)[0]
            rows[obj["id"]] = dict(
                stix_id=obj["id"],
                attack_id=attack_id,
                name=obj.get("name", ""),
                description=obj.get("description"),
                tactics=_canonical_tactics(raw_phases, report),
                platforms=obj.get("x_mitre_platforms", []) or [],
                detection_strategy_refs=[],
                is_subtechnique=is_sub,
                parent_attack_id=parent,
                # x_mitre_deprecated folds onto the revoked flag: the schema
                # has no dedicated deprecation column and every consumer
                # filters Technique.revoked for "alive", so deprecated rows
                # are kept but flagged revoked (row counts unchanged).
                revoked=bool(obj.get("revoked", False))
                or bool(obj.get("x_mitre_deprecated", False)),
            )
        elif t == "relationship" and obj.get("relationship_type") == "detects":
            # detection-strategy --detects--> attack-pattern
            tgt, src = obj.get("target_ref"), obj.get("source_ref")
            if tgt and src and tgt.startswith("attack-pattern--"):
                detects.setdefault(tgt, []).append(src)
    for sid, strat_ids in detects.items():
        if sid in rows:
            rows[sid]["detection_strategy_refs"] = sorted(set(strat_ids))
    return list(rows.values())


def load_all(
    session: Session,
    domain: str = "enterprise-attack",
    refresh: bool = False,
) -> LoadReport:
    """Load ATT&CK data into the DB. Uses the local cache unless refresh=True."""
    report = LoadReport()
    if refresh:
        from .client import get_client, snapshot_from, _fetch_objects

        logger.info("Refreshing ATT&CK %s via mitreattack-python ...", domain)
        objs = _fetch_objects(get_client(domain))
        snap = snapshot_from(objs)
        cache_path = Path(DEFAULT_CACHE)
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(objs), encoding="utf-8")
        data = objs
    else:
        logger.info("Loading ATT&CK %s (cache-first) ...", domain)
        snap, data = load_or_fetch(domain)
    report.snapshot = snap
    logger.info(
        "Bundle v%s (%s): %d objects",
        snap.bundle_version, snap.bundle_date, snap.object_count,
    )

    techniques = _technique_rows(data, report)
    strategies, analytics_by_sid = [], {}
    groups, group_techniques = {}, []  # (group_stix_id, technique_stix_id)
    strategy_technique: dict[str, str] = {}

    for obj in data:
        t = obj.get("type")
        if t == "x-mitre-detection-strategy":
            strategy_technique[obj["id"]] = None  # filled via detects rels below
            strategies.append(dict(stix_id=obj["id"], det_id=stix_external_id(obj),
                                   name=obj.get("name", ""), technique_stix_id=None))
        elif t == "x-mitre-analytic":
            analytics_by_sid.setdefault(obj["id"], obj)
        elif t == "intrusion-set":
            gid = stix_external_id(obj)
            if gid:
                groups[obj["id"]] = dict(
                    stix_id=obj["id"], group_id=gid, name=obj.get("name", ""),
                    aliases=obj.get("aliases", []) or [],
                    description=obj.get("description"),
                )
        elif t == "relationship" and obj.get("relationship_type") == "uses":
            src, tgt = obj.get("source_ref"), obj.get("target_ref")
            if src and tgt and src.startswith("intrusion-set--") \
                    and tgt.startswith("attack-pattern--"):
                group_techniques.append((src, tgt))

    # Link strategies to techniques through 'detects' relationships.
    detects_pairs: dict[str, str] = {}
    for obj in data:
        if obj.get("type") == "relationship" \
                and obj.get("relationship_type") == "detects":
            src, tgt = obj.get("source_ref"), obj.get("target_ref")
            if src and tgt and src.startswith("x-mitre-detection-strategy--"):
                detects_pairs[src] = tgt
    tech_by_stix = {t["stix_id"]: t for t in techniques}
    valid_strategy_ids = {s["stix_id"] for s in strategies}
    for s in strategies:
        tgt = detects_pairs.get(s["stix_id"])
        if tgt and tgt in tech_by_stix:
            s["technique_stix_id"] = tgt
        else:
            report.warnings += 1  # orphan strategy (technique revoked/etc.)

    valid_tech_ids = {t["stix_id"]: t for t in techniques}
    analytics_rows: list[dict] = []
    for a_sid, obj in analytics_by_sid.items():
        an = dict(
            stix_id=a_sid,
            an_id=stix_external_id(obj),
            name=obj.get("name"),
            description=obj.get("description"),
            strategy_stix_id=None,
            log_source_refs=[
                ls.get("x_mitre_data_component_ref")
                for ls in obj.get("x_mitre_log_source_references", []) or []
                if ls.get("x_mitre_data_component_ref")
            ],
        )
        analytics_rows.append(an)

    # Analytics attach to their strategy via each strategy's analytic refs.
    strat_analytic_refs: dict[str, list[str]] = {}
    for obj in data:
        if obj.get("type") == "x-mitre-detection-strategy":
            refs = obj.get("x_mitre_analytic_refs", []) or []
            strat_analytic_refs[obj["id"]] = refs
    an_by_id = {a["stix_id"]: a for a in analytics_rows}
    for s_sid, refs in strat_analytic_refs.items():
        for r in refs:
            a = an_by_id.get(r)
            if a is not None:
                a["strategy_stix_id"] = s_sid

    # --- ordered upserts -------------------------------------------------
    for row in techniques:
        session.merge(Technique(**row))
    report.counts["techniques"] = len(techniques)

    for s in strategies:
        session.merge(DetectionStrategy(**s))
    report.counts["detection_strategies"] = len(strategies)

    for a in analytics_rows:
        session.merge(Analytic(**a))
    report.counts["analytics"] = len(analytics_rows)

    # Parents BEFORE children: Postgres enforces FKs immediately, so
    # apt_groups rows must exist before apt_technique rows flush.
    for g in groups.values():
        session.merge(AptGroup(**g))
    report.counts["apt_groups"] = len(groups)

    known_groups = set(groups)
    n_rel = 0
    for g_sid, t_sid in group_techniques:
        if g_sid in known_groups and t_sid in valid_tech_ids:
            session.merge(AptTechnique(group_stix_id=g_sid, technique_stix_id=t_sid))
            n_rel += 1
    report.counts["group_techniques"] = n_rel

    meta = session.get(AttackMeta, 1) or AttackMeta(id=1)
    meta.library_version = snap.library_version
    meta.bundle_version = snap.bundle_version
    meta.bundle_date = snap.bundle_date
    meta.object_count = snap.object_count
    meta.loaded_at = utcnow()
    session.add(meta)

    logger.info(
        "Load complete: %s (warnings=%d, unknown_phases=%d)",
        report.counts, report.warnings, report.unknown_phase_count,
    )
    return report
