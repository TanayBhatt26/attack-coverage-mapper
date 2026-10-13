"""SigmaHQ rule index and logsource mapper (Phase 5 Wave 2 — foundation).

Two capabilities for the hunt-query pipeline:

1. :class:`SigmaIndex` -- an in-memory ``dict[technique_id -> sorted rule paths]``
   built by scanning a SigmaHQ clone directory.  The build uses a *whole-file*
   regex (no YAML parse at build time, per Wave 1 finding: 3144 rules, parse is
   deferred to conversion).  Tag format is verified lowercase ``attack.tXXXX``
   / ``attack.tXXXX.YYY`` (``research/p5-wave1-full-results.md`` agent-416); the
   captured ``t`` is uppercased to the DB form ``TXXXX``.

2. :class:`LogsourceMapper` -- maps each *config* source format (``evtx``,
   ``aws_cloudtrail``, ``zeek``, ``syslog``, ``nginx``, ``cef``, ``leef``,
   ``json``) to the set of Sigma ``logsource`` predicates (product/category/
   service tuples) that format collects.  This drives dispatch step 2: does a
   candidate Sigma rule's logsource actually target the closable/contributing
   source?  The mapping is the Wave-1 logsource-alignment finding
   (``research/p5-wave1-full-results.md`` agent-423).

The index is deliberately shallow: it knows *which* rules tag a technique and
whether their logsource *could* match a format.  Rule scoring, pySigma
conversion, and attribution live in the higher layers
(:mod:`detections.hand_written`, the future conversion cache).
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from pathlib import Path
from typing import Iterable

logger = logging.getLogger(__name__)

__all__ = ("FORMAT_TO_LOGSOURCES", "LogsourceMapper", "SigmaIndex")

# ---------------------------------------------------------------------------
# Tag extraction
# ---------------------------------------------------------------------------

# Verified against the live SigmaHQ corpus (agent-416): every technique tag is
# lowercase ``attack.t####`` or ``attack.t####.###``.  The capture group grabs
# the leading ``t`` + digits; the build uppercases the ``t`` -> ``T`` to match
# the canonical DB form validated by ``parser.mappings_io.TECHNIQUE_ID_PATTERN``.
_TAG_TECHNIQUE_RE = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)

# File extensions that carry Sigma rules in the clone.
_RULE_EXTENSIONS = frozenset({".yml", ".yaml"})


def _normalize_technique(token: str) -> str:
    """Uppercase the leading ``t`` of a captured tag token to DB form.

    Args:
        token: A regex capture such as ``t1059.001`` (any case).

    Returns:
        Canonical id such as ``T1059.001``.
    """
    if token.startswith("t"):
        return "T" + token[1:]
    return token


# ---------------------------------------------------------------------------
# Logsource mapper
# ---------------------------------------------------------------------------

# Each config source format maps to the Sigma logsource predicates that format
# collects.  A predicate is a partial ``{product, category, service}`` dict; a
# rule's logsource matches a predicate when *every* key in the predicate equals
# the rule's logsource value for that key (predicates are intentionally
# partial -- ``{"product": "windows"}`` matches any Windows rule regardless of
# category/service).  Source: Wave-1 logsource-alignment (agent-423) measured
# against the SigmaHQ taxonomy.
FORMAT_TO_LOGSOURCES: dict[str, tuple[dict[str, str], ...]] = {
    # EVTX spans the entire product:windows tree (36 categories, 50 services).
    "evtx": ({"product": "windows"},),
    # CloudTrail is the one AWS service we ingest as a distinct format.
    "aws_cloudtrail": ({"product": "aws", "service": "cloudtrail"},),
    # Zeek rules are keyed on product:zeek with a service per log flavour.
    "zeek": (
        {"product": "zeek", "service": "dce_rpc"},
        {"product": "zeek", "service": "dns"},
        {"product": "zeek", "service": "http"},
        {"product": "zeek", "service": "kerberos"},
        {"product": "zeek", "service": "rdp"},
        {"product": "zeek", "service": "smb_files"},
        {"product": "zeek", "service": "x509"},
    ),
    # Syslog maps to the linux product tree (auditd/auth/sshd/cron/sudo/...).
    "syslog": (
        {"product": "linux", "category": "process_creation"},
        {"product": "linux", "category": "file_event"},
        {"product": "linux", "category": "network_connection"},
        {"product": "linux", "service": "auditd"},
        {"product": "linux", "service": "auth"},
        {"product": "linux", "service": "clamav"},
        {"product": "linux", "service": "cron"},
        {"product": "linux", "service": "sudo"},
        {"product": "linux", "service": "sshd"},
        {"product": "linux", "service": "syslog"},
        {"product": "linux", "service": "vsftpd"},
    ),
    # nginx has no dedicated Sigma product; the closest is category:webserver.
    "nginx": ({"category": "webserver"},),
    # CEF is a network-security-device format -> category:firewall.
    "cef": ({"category": "firewall"},),
    # LEEF (QRadar / network device) -> category:firewall as well.
    "leef": ({"category": "firewall"},),
    # json is the ECS/OCSF-agnostic catch-all; a wide set of categories.
    "json": (
        {"category": "firewall"},
        {"category": "proxy"},
        {"category": "dns"},
        {"category": "webserver"},
        {"category": "antivirus"},
        {"category": "database"},
    ),
}


class LogsourceMapper:
    """Map config source formats to Sigma logsource predicates.

    Static, stateless helper: all data lives in :data:`FORMAT_TO_LOGSOURCES`.
    The predicate model is deliberately partial-match so a single
    ``{"product": "windows"}`` predicate covers the whole EVTX surface without
    enumerating 36 categories.
    """

    @staticmethod
    def predicates_for(source_format: str) -> tuple[dict[str, str], ...]:
        """Return the predicate set a format collects.

        Args:
            source_format: Config format key (e.g. ``'evtx'``).

        Returns:
            Tuple of partial logsource dicts; empty when the format is
            unknown (no predicate ever matches).
        """
        return FORMAT_TO_LOGSOURCES.get(source_format, ())

    @classmethod
    def matches(
        cls,
        rule_logsource: Mapping[str, str | None] | None,
        source_format: str,
    ) -> bool:
        """True when a Sigma rule's logsource could fire on *source_format*.

        A rule matches when its logsource satisfies *at least one* of the
        format's predicates (see :data:`FORMAT_TO_LOGSOURCES` for the model).

        Args:
            rule_logsource: A Sigma ``logsource`` mapping, e.g.
                ``{"product": "windows", "category": "process_creation"}``.
                ``None`` / empty only matches formats with no product/category
                constraint (there are none today), so unknown logsources never
                falsely match.
            source_format: Config format key to test against.

        Returns:
            True if the rule's logsource matches any predicate for the format.
        """
        if not rule_logsource:
            return False
        for predicate in cls.predicates_for(source_format):
            if all(rule_logsource.get(k) == v for k, v in predicate.items()):
                return True
        return False


# ---------------------------------------------------------------------------
# Sigma rule index
# ---------------------------------------------------------------------------


class SigmaIndex:
    """In-memory index: technique id -> sorted list of Sigma rule file paths.

    Built by :meth:`from_clone` from a shallow SigmaHQ clone directory.  The
    build scans every ``.yml``/``.yaml`` file with a whole-file regex (no YAML
    parse -- parse is deferred to pySigma conversion, keeping the build fast
    and tolerant of rules the installed pySigma cannot yet parse).

    The index is immutable after construction: it is a ``tuple``-valued dict so
    callers may cache it freely.
    """

    def __init__(self, index: Mapping[str, Iterable[str]]) -> None:
        """Direct constructor (mostly for tests).

        Args:
            index: Mapping technique id -> iterable of rule file paths.  Paths
                are deduplicated per technique and stored sorted.
        """
        self._index: dict[str, tuple[str, ...]] = {
            tech: tuple(sorted(set(paths))) for tech, paths in index.items()
        }

    @classmethod
    def from_clone(cls, clone_dir: str | Path) -> SigmaIndex:
        """Scan a SigmaHQ clone and build the technique -> rule-path index.

        Graceful on absence: if ``clone_dir`` does not exist (no SigmaHQ clone
        available), a WARNING is logged and an empty index is returned so the
        pipeline falls back to hand-curated / generic-query paths.  A clone
        directory with no rule files likewise yields an empty index.

        Args:
            clone_dir: Root of a SigmaHQ/sigma clone (the ``rules/``
                subdirectory is scanned, but any ``.yml``/``.yaml`` under the
                root is walked so a partial checkout still works).

        Returns:
            A populated :class:`SigmaIndex`.
        """
        root = Path(clone_dir)
        if not root.is_dir():
            logger.warning(
                "SigmaHQ clone not found at %s — SigmaIndex empty "
                "(hunt queries will fall back to curated / generic)",
                root,
            )
            return cls({})

        # technique -> set of rule file paths.  A single rule can carry several
        # technique tags; a technique can be tagged across many rules.
        tech_to_paths: dict[str, set[str]] = defaultdict(set)
        rule_files = sorted(
            p
            for p in root.rglob("*")
            if p.is_file() and p.suffix.lower() in _RULE_EXTENSIONS
        )

        for rule_path in rule_files:
            try:
                text = rule_path.read_text(encoding="utf-8", errors="replace")
            except OSError as err:
                logger.debug("skip unreadable rule %s: %s", rule_path, err)
                continue
            # Dedup tags within one file: a rule tagging the same technique
            # twice should map to the rule only once.
            tags = set(_TAG_TECHNIQUE_RE.findall(text))
            if not tags:
                continue
            for token in tags:
                tech_to_paths[_normalize_technique(token)].add(str(rule_path))

        index = cls(tech_to_paths)
        logger.info(
            "SigmaIndex built from %s: %d rules, %d distinct techniques",
            root,
            len(rule_files),
            len(index._index),
        )
        return index

    def get(self, technique_id: str) -> list[str]:
        """Return sorted rule paths tagged with *technique_id*.

        Args:
            technique_id: Technique id in DB form (``T1059.001`` or the
                lowercase ``t1059.001`` -- both normalize to the same key).

        Returns:
            Sorted, deduplicated rule paths; empty list when the technique is
            not indexed.  The returned list is a fresh mutable copy.
        """
        key = _normalize_technique(technique_id)
        return list(self._index.get(key, ()))

    def techniques(self) -> tuple[str, ...]:
        """All technique ids present in the index, sorted."""
        return tuple(sorted(self._index))

    def __len__(self) -> int:
        return len(self._index)

    def __contains__(self, technique_id: str) -> bool:
        return _normalize_technique(technique_id) in self._index
