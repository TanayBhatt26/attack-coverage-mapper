"""Thin adapter around mitreattack-python for ATT&CK Enterprise data.

Per blueprint section 3.2: ATT&CK data access goes through the official
library (first fetch). Objects are then serialized to plain dicts and cached
locally so re-loads are offline, fast, and version-pinned. The current
library release does not expose x-mitre-collection metadata through its
query API, so the snapshot is pinned as *derived*: library version +
max(modified) across all fetched objects.
"""
import json
from dataclasses import dataclass
from pathlib import Path

try:
    from importlib.metadata import version as _pkg_version
except ImportError:  # pragma: no cover
    _pkg_version = lambda name: "unknown"  # noqa: E731

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CACHE = REPO_ROOT / "data" / "attack_stix" / "enterprise-attack.json"

WANTED_TYPES = (
    "attack-pattern",
    "intrusion-set",
    "x-mitre-detection-strategy",
    "x-mitre-analytic",
    "relationship",
)
CUSTOM_TYPES = ("x-mitre-detection-strategy", "x-mitre-analytic")


@dataclass(frozen=True)
class SnapshotInfo:
    library_version: str
    bundle_version: str | None
    bundle_date: str | None
    object_count: int


def get_client(domain: str = "enterprise-attack"):
    """Return a MitreAttackData over the downloaded enterprise bundle."""
    from mitreattack.attackToExcel.attackToExcel import get_stix_data
    from mitreattack.stix20 import MitreAttackData

    data_store = get_stix_data(domain)
    return MitreAttackData(src=data_store)


def _iter_type(client, stix_type: str) -> list:
    getter = getattr(client, "get_objects_by_type", None)
    if getter is not None:
        return list(getter(stix_type))
    return list(client.src.query([{"type": stix_type}]))  # pragma: no cover


def _custom_to_dict(o) -> dict:
    """mitreattack's custom STIX objects raise on serialize(); harvest the
    exact fields the loader needs instead."""
    extrefs = []
    for r in getattr(o, "external_references", None) or []:
        extrefs.append(
            {
                "source_name": getattr(r, "source_name", None),
                "external_id": getattr(r, "external_id", None),
                "url": getattr(r, "url", None),
            }
        )
    log_sources = []
    for ls in getattr(o, "x_mitre_log_source_references", None) or []:
        ref = getattr(ls, "x_mitre_data_component_ref", None)
        if ref is None and isinstance(ls, dict):
            ref = ls.get("x_mitre_data_component_ref")
        if ref:
            log_sources.append({"x_mitre_data_component_ref": ref})
    d: dict = {
        "id": o.id,
        "type": getattr(o, "type", o.__class__.__name__.lower()),
        "name": getattr(o, "name", None),
        "description": getattr(o, "description", None),
    }
    if extrefs:
        d["external_references"] = extrefs
    ver = getattr(o, "x_mitre_version", None)
    if ver:
        d["x_mitre_version"] = ver
    an_refs = getattr(o, "x_mitre_analytic_refs", None)
    if an_refs:
        d["x_mitre_analytic_refs"] = list(an_refs)
    if log_sources:
        d["x_mitre_log_source_references"] = log_sources
    return d


def _fetch_objects(client) -> list[dict]:
    objs: list[dict] = []
    seen: set[str] = set()
    for stix_type in WANTED_TYPES:
        for obj in _iter_type(client, stix_type):
            if obj.id in seen:
                continue
            seen.add(obj.id)
            if stix_type in CUSTOM_TYPES:
                objs.append(_custom_to_dict(obj))
            else:
                objs.append(json.loads(obj.serialize()))
    return objs


def snapshot_from(objs: list[dict]) -> SnapshotInfo:
    """Pin snapshot metadata: library version + derived bundle date.

    The library does not expose collection-level versioning, so the bundle
    date is derived as max(modified) across fetched objects.
    """
    dates = [o.get("modified") for o in objs if o.get("modified")]
    return SnapshotInfo(
        library_version=_pkg_version("mitreattack-python"),
        bundle_version=None,
        bundle_date=max(dates) if dates else None,
        object_count=len(objs),
    )


def load_or_fetch(
    domain: str = "enterprise-attack", cache_path: Path | None = None
) -> tuple[SnapshotInfo, list[dict]]:
    """Load from the local cache when present; otherwise fetch via the official
    library once and persist the cache."""
    cache_path = Path(cache_path) if cache_path else DEFAULT_CACHE
    if cache_path.exists():
        objs = json.loads(cache_path.read_text(encoding="utf-8"))
        return snapshot_from(objs), objs
    objs = _fetch_objects(get_client(domain))
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(objs), encoding="utf-8")
    return snapshot_from(objs), objs


def stix_external_id(obj: dict) -> str | None:
    """Extract the ATT&CK ID (T####[.###] / G#### ...) from external_references."""
    for ref in obj.get("external_references", []) or []:
        ext_id = ref.get("external_id")
        source = ref.get("source_name")
        if ext_id and source in ("mitre-attack", "mitre"):
            return ext_id
    return None
