"""ATT&CK mapping-rule model and strict CSV loader.

A mapping rule ties one format-specific log signal to exactly one ATT&CK
technique. Rules live in ``data/attack_mappings.csv`` - 14 columns, one
rule per row - and feed the matching engine in
:mod:`parser.attack_mapper`.

Columns (fixed names, order-insensitive):

- ``mapping_id``: unique rule identifier such as ``M001``.
- ``source_format``: one of the supported parser formats
  (see ``VALID_SOURCE_FORMATS``).
- ``event_action_pattern``: regex matched against ``event.event_action``;
  an empty cell means "no action constraint" (stored as ``None``).
- ``ext_keys``: whitespace-separated extension key names, lowercased on
  load; an empty cell yields an empty tuple.
- ``ext_value_pattern``: optional regex applied to the matched extension
  value; an empty cell is stored as ``None``.
- ``match_type``: one of ``exact``, ``regex``, ``exists``, ``heuristic``.
- ``is_core``: case-insensitive ``true``/``false``.
- ``technique_id``: ATT&CK technique/sub-technique id (``T####`` or
  ``T####.###``).
- ``tactic``: ATT&CK tactic slug such as ``credential-access``.
- ``base_confidence``: prior confidence in [0.0, 1.0].
- ``visibility_hint``: telemetry visibility weight in [0, 4].
- ``evidence_ref``: citation URL or reference text.
- ``sigma_rule_id``: optional related Sigma rule UUID; empty -> ``None``.
- ``notes``: free-form analyst notes.

Any malformed row - wrong column count, unknown source format, invalid
regex, bad technique id, out-of-range number, duplicate id - raises
:class:`ValueError` naming the file, row number and ``mapping_id`` so a
broken curated entry cannot slip through unnoticed.
"""

import csv
import dataclasses
import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

#: Repository-root-relative location of the curated mapping rules. Resolved
#: from this file rather than the process CWD, so the dashboard keeps working
#: no matter which directory Streamlit was launched from.
_REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MAPPINGS_PATH = _REPO_ROOT / "data" / "attack_mappings.csv"

#: Log formats accepted in the ``source_format`` column; mirrors the
#: parsers exposed by :mod:`parser.siem_parsers`.
VALID_SOURCE_FORMATS = frozenset(
    {"syslog", "cef", "leef", "json", "evtx", "aws_cloudtrail", "nginx", "zeek"}
)

#: Allowed values for the ``match_type`` column.
VALID_MATCH_TYPES = frozenset({"exact", "regex", "exists", "heuristic"})

#: Shape of a valid ATT&CK technique / sub-technique identifier.
TECHNIQUE_ID_PATTERN = r"^T\d{4}(\.\d{3})?$"

#: Exact column names the CSV must provide (14 columns).
EXPECTED_COLUMNS = (
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


@dataclasses.dataclass(frozen=True)
class MappingRule:
    """One immutable ATT&CK mapping parsed from a mappings CSV row.

    Attributes:
        mapping_id: Unique rule identifier (``M001``-style).
        source_format: Parser format this rule applies to; always one of
            ``VALID_SOURCE_FORMATS``.
        event_action_re: Compiled regex for the ``event_action_pattern``
            cell, or ``None`` when the cell was empty.
        ext_keys: Lowercased extension key names the rule may match on;
            possibly empty.
        ext_value_re: Compiled regex for the ``ext_value_pattern`` cell,
            or ``None`` when the cell was empty.
        match_type: One of ``exact``, ``regex``, ``exists``, ``heuristic``.
        is_core: Whether this is a curated core rule.
        technique_id: Validated ATT&CK technique/sub-technique id.
        tactic: ATT&CK tactic slug.
        base_confidence: Prior confidence in [0.0, 1.0].
        visibility_hint: Telemetry visibility weight in [0, 4].
        evidence_ref: Citation for the mapping.
        sigma_rule_id: Related Sigma rule UUID, or ``None``.
        notes: Free-form notes.
    """

    mapping_id: str
    source_format: str
    event_action_re: re.Pattern[str] | None
    ext_keys: tuple[str, ...]
    ext_value_re: re.Pattern[str] | None
    match_type: str
    is_core: bool
    technique_id: str
    tactic: str
    base_confidence: float
    visibility_hint: int
    evidence_ref: str
    sigma_rule_id: str | None
    notes: str


def _compile_or_none(pattern: str) -> re.Pattern[str] | None:
    """Compile ``pattern``, returning ``None`` for an empty cell."""
    if not pattern:
        return None
    return re.compile(pattern)


def _build_rule(cells: dict[str, str], prefix: str) -> MappingRule:
    """Validate one stripped row of cells and build its :class:`MappingRule`.

    Args:
        cells: Column name -> stripped cell text for a single data row.
        prefix: Error-message prefix already containing file, row number
            and mapping id context.

    Returns:
        The fully validated :class:`MappingRule`.

    Raises:
        ValueError: On any schema or domain violation; the message starts
            with ``prefix`` so callers can locate the offending row.
    """
    source_format = cells["source_format"]
    if source_format not in VALID_SOURCE_FORMATS:
        raise ValueError(
            f"{prefix}unknown source_format {source_format!r}; "
            f"expected one of {sorted(VALID_SOURCE_FORMATS)}"
        )

    match_type = cells["match_type"]
    if match_type not in VALID_MATCH_TYPES:
        raise ValueError(
            f"{prefix}unknown match_type {match_type!r}; "
            f"expected one of {sorted(VALID_MATCH_TYPES)}"
        )

    core_raw = cells["is_core"].lower()
    if core_raw == "true":
        is_core = True
    elif core_raw == "false":
        is_core = False
    else:
        raise ValueError(
            f"{prefix}is_core must be true/false (case-insensitive), got {cells['is_core']!r}"
        )

    technique_id = cells["technique_id"]
    if not re.fullmatch(TECHNIQUE_ID_PATTERN, technique_id):
        raise ValueError(
            f"{prefix}invalid technique_id {technique_id!r}; expected T#### or T####.###"
        )

    tactic = cells["tactic"]
    if not tactic:
        raise ValueError(f"{prefix}tactic must be non-empty")

    try:
        base_confidence = float(cells["base_confidence"])
    except ValueError:
        raise ValueError(
            f"{prefix}base_confidence must be a number, got {cells['base_confidence']!r}"
        ) from None
    if not 0.0 <= base_confidence <= 1.0:
        raise ValueError(
            f"{prefix}base_confidence must be within [0.0, 1.0], got {base_confidence}"
        )

    try:
        visibility_hint = int(cells["visibility_hint"])
    except ValueError:
        raise ValueError(
            f"{prefix}visibility_hint must be an integer, got {cells['visibility_hint']!r}"
        ) from None
    if not 0 <= visibility_hint <= 4:
        raise ValueError(
            f"{prefix}visibility_hint must be within [0, 4], got {visibility_hint}"
        )

    ext_keys = tuple(key.lower() for key in cells["ext_keys"].split())

    try:
        event_action_re = _compile_or_none(cells["event_action_pattern"])
    except re.error as err:
        raise ValueError(
            f"{prefix}invalid event_action_pattern {cells['event_action_pattern']!r}: {err}"
        ) from err
    try:
        ext_value_re = _compile_or_none(cells["ext_value_pattern"])
    except re.error as err:
        raise ValueError(
            f"{prefix}invalid ext_value_pattern {cells['ext_value_pattern']!r}: {err}"
        ) from err
    # 'exists' rows match on key presence alone; any value-pattern cell is
    # documentation of the expected content, never an additional filter.
    if match_type == "exists":
        ext_value_re = None

    return MappingRule(
        mapping_id=cells["mapping_id"],
        source_format=source_format,
        event_action_re=event_action_re,
        ext_keys=ext_keys,
        ext_value_re=ext_value_re,
        match_type=match_type,
        is_core=is_core,
        technique_id=technique_id,
        tactic=tactic,
        base_confidence=base_confidence,
        visibility_hint=visibility_hint,
        evidence_ref=cells["evidence_ref"],
        sigma_rule_id=cells["sigma_rule_id"] or None,
        notes=cells["notes"],
    )


def load_mappings(path: str | Path) -> list[MappingRule]:
    """Load and strictly validate mapping rules from a CSV file.

    The file must start with a header carrying exactly the 14 expected
    column names (any order) and one well-formed rule per data row. All
    cells are whitespace-stripped before validation; empty pattern cells
    become ``None`` regexes and an empty ``sigma_rule_id`` becomes
    ``None``.

    Args:
        path: Path to the mappings CSV (typically
            ``data/attack_mappings.csv``).

    Returns:
        Rules in file order.

    Raises:
        FileNotFoundError: If ``path`` does not exist (natural ``open()``
            behaviour).
        ValueError: If the header is missing/duplicated/wrong, a data row
            has the wrong number of columns, or any cell violates its
            schema (unknown source format, bad regex, bad technique id,
            out-of-range numbers, invalid booleans, duplicate
            ``mapping_id``). Messages always name the offending row
            number and ``mapping_id``.
    """
    rules: list[MappingRule] = []
    seen_ids: dict[str, int] = {}

    with open(path, "r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        fieldnames = reader.fieldnames
        if not fieldnames:
            raise ValueError(f"{path}: missing header row")
        if len(fieldnames) != len(set(fieldnames)):
            duplicates = sorted({n for n in fieldnames if fieldnames.count(n) > 1})
            raise ValueError(f"{path}: duplicated header column(s): {duplicates}")
        if sorted(fieldnames) != sorted(EXPECTED_COLUMNS):
            missing = sorted(set(EXPECTED_COLUMNS) - set(fieldnames))
            unexpected = sorted(set(fieldnames) - set(EXPECTED_COLUMNS))
            raise ValueError(
                f"{path}: bad header; expected exactly the 14 columns "
                f"{list(EXPECTED_COLUMNS)}, missing={missing}, unexpected={unexpected}"
            )

        for rownum, row in enumerate(reader, start=2):
            extras = row.get(None)
            if extras:
                raise ValueError(
                    f"{path}: row {rownum}: expected {len(EXPECTED_COLUMNS)} columns, "
                    f"found extra value(s) {extras!r}"
                )
            missing_cells = [name for name in EXPECTED_COLUMNS if row.get(name) is None]
            if missing_cells:
                raise ValueError(
                    f"{path}: row {rownum}: missing value(s) for column(s) {missing_cells}"
                )
            cells = {name: (row[name] or "").strip() for name in EXPECTED_COLUMNS}

            mapping_id = cells["mapping_id"]
            if not mapping_id:
                raise ValueError(f"{path}: row {rownum}: mapping_id must be non-empty")

            if mapping_id in seen_ids:
                raise ValueError(
                    f"{path}: row {rownum} ({mapping_id}): duplicate mapping_id "
                    f"(first defined on row {seen_ids[mapping_id]})"
                )
            seen_ids[mapping_id] = rownum

            rules.append(_build_rule(cells, f"{path}: row {rownum} ({mapping_id}): "))

    logger.debug("Loaded %d mapping rules from %s", len(rules), path)
    return rules
