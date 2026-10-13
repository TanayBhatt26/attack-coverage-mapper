"""attack_mapper.py -- Tiered ATT&CK technique matching engine.

Annotates normalized :class:`~parser.log_event_bridge.LogEvent` objects with
ATT&CK techniques, tactics, a datasource label, and a detection confidence
score by applying curated :class:`~parser.mappings_io.MappingRule` entries.

Matching is tiered per candidate rule (rules whose ``source_format`` equals
the event's):

* **Tier 1 -- extension evidence**: the rule declares extension keys, at
  least one is present on the event, and the optional value pattern matches.
  Scores ``base_confidence * 1.0``.
* **Tier 2 -- event-action match**: the rule declares no extension keys and
  its action pattern fully matches the event action.
  Scores ``base_confidence * 0.85``.
* **Tier 3 -- format-level weak heuristic**: evaluated only when *zero*
  tier 1/2 matches exist across all candidate rules. A ``heuristic`` rule
  contributes ``base_confidence * 0.40`` when its declared checks pass.

Every produced score is capped at 0.95. Matches are deduplicated per
technique id keeping the highest score; tactics are the sorted union over
the kept rules. Sources disabled via ``config["enabled_log_sources"]`` skip
matching entirely and get their ATT&CK annotations cleared.
"""

import logging
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from parser.log_event_bridge import LogEvent
from parser.mappings_io import MappingRule

logger = logging.getLogger(__name__)

# Confidence multiplier applied per matching tier (tier number -> factor).
_TIER_MULTIPLIERS = {1: 1.0, 2: 0.85, 3: 0.40}

# Upper bound for any detection confidence score emitted by this engine.
_MAX_CONFIDENCE = 0.95

# Static log-format -> ATT&CK datasource label mapping.
_DATASOURCE_BY_FORMAT = {
    "evtx": "windows:eventlog",
    "syslog": "linux:syslog",
    "cef": "network:device",
    "leef": "network:device",
    "json": "generic:json",
    "aws_cloudtrail": "cloud:cloudtrail",
    "nginx": "web:access",
    "zeek": "network:zeek",
}


def score_for_tier(base_confidence: float, tier: int) -> float:
    """Return the confidence for ``base_confidence`` scored at ``tier``.

    Tier 1 keeps the base confidence as-is, tier 2 applies a 0.85 factor,
    and tier 3 applies a 0.40 factor. Every result is capped at 0.95.

    Raises:
        ValueError: if ``tier`` is not one of 1, 2, or 3.
    """
    try:
        multiplier = _TIER_MULTIPLIERS[tier]
    except KeyError:
        raise ValueError(f"unknown matching tier: {tier!r}") from None
    return min(base_confidence * multiplier, _MAX_CONFIDENCE)


def map_log_event(
    event: LogEvent,
    rules: Sequence[MappingRule],
    config: Mapping[str, Any],
) -> LogEvent:
    """Match a single event against the rules and annotate it in place.

    Candidate rules are those whose ``source_format`` equals
    ``event.source_format``. Strict rules (any ``match_type`` other than
    ``heuristic``) are evaluated at tier 1 (declared extension keys present,
    optional value pattern matched) or tier 2 (declared action pattern fully
    matches the event action). Only when no strict rule matched at either
    tier do ``heuristic`` rules contribute, at tier 3, provided their
    declared checks pass. Scores are capped at 0.95 and deduplicated per
    technique id keeping the highest score.

    Sets ``attack_technique_ids`` (sorted), ``attack_tactics`` (sorted union
    of the kept rules' tactics), ``detection_confidence`` (highest kept
    score, 0.0 when nothing matched), and ``datasource_type`` (static
    format mapping, ``"unknown:<format>"`` as fallback).

    When ``config["enabled_log_sources"].get(source_format)`` is exactly
    ``False``, matching is skipped and the ATT&CK annotations are cleared;
    ``datasource_type`` is still assigned.

    Returns:
        LogEvent: the same event instance, annotated.
    """
    source_format = event.source_format
    event.datasource_type = _datasource_for_format(source_format)

    enabled_sources = (config or {}).get("enabled_log_sources") or {}
    if enabled_sources.get(source_format) is False:
        logger.debug(
            "log source %r is disabled; clearing ATT&CK annotations", source_format
        )
        event.attack_technique_ids = []
        event.attack_tactics = []
        event.detection_confidence = 0.0
        return event

    lowered_extensions = {
        key.lower(): value for key, value in event.extensions.items()
    }

    # Deduplicated matches: technique_id -> (confidence, kept rule).
    matches: Dict[str, Any] = {}
    strict_matched = False

    for rule in rules:
        if rule.source_format != source_format or rule.match_type == "heuristic":
            continue
        tier = _strict_tier_for_rule(rule, event, lowered_extensions)
        if tier is None:
            continue
        strict_matched = True
        _record_match(matches, rule, score_for_tier(rule.base_confidence, tier))

    if not strict_matched:
        for rule in rules:
            if rule.source_format != source_format or rule.match_type != "heuristic":
                continue
            if _heuristic_checks_pass(rule, event, lowered_extensions):
                _record_match(matches, rule, score_for_tier(rule.base_confidence, 3))

    kept = list(matches.values())
    event.attack_technique_ids = sorted(matches)
    event.attack_tactics = sorted({rule.tactic for _, rule in kept})
    event.detection_confidence = max((score for score, _ in kept), default=0.0)

    logger.debug(
        "mapped %s event %s -> %d technique(s), confidence %.2f",
        source_format,
        event.event_id,
        len(kept),
        event.detection_confidence,
    )
    return event


def map_events(
    events: Iterable[LogEvent],
    rules: Sequence[MappingRule],
    config: Mapping[str, Any],
) -> List[LogEvent]:
    """Map an iterable of events through :func:`map_log_event`.

    Returns:
        list[LogEvent]: the same event objects, each annotated in place.
    """
    return [map_log_event(event, rules, config) for event in events]


# --- internal helpers -------------------------------------------------------


def _datasource_for_format(source_format: str) -> str:
    """Return the static ATT&CK datasource label for a log format."""
    return _DATASOURCE_BY_FORMAT.get(source_format, f"unknown:{source_format}")


# Hostile input guard: regex value checks run against at most this many
# characters of any extension value. Measured backtracking on the cradle
# pattern grows ~3.9x per doubling beyond ~2k chars; truncation bounds the
# worst case to milliseconds while real-world fields never approach it.
MAX_REGEX_INPUT_CHARS = 4000


def _bounded(value: Any) -> str:
    text = str(value)
    return text[:MAX_REGEX_INPUT_CHARS]


def _extension_checks_pass(
    rule: MappingRule, lowered_extensions: Mapping[str, Any]
) -> bool:
    """Evaluate a rule's extension-key declaration against an event.

    The first declared key found on the event decides the outcome: the
    optional value pattern is applied to that key's value only (length-
    bounded - see :data:`MAX_REGEX_INPUT_CHARS`).
    """
    for key in rule.ext_keys:
        if key in lowered_extensions:
            if rule.ext_value_re is None:
                return True
            value = lowered_extensions[key]
            return rule.ext_value_re.search(_bounded(value)) is not None
    return False


def _action_check_passes(rule: MappingRule, event_action: Optional[str]) -> bool:
    """Return whether the rule's action pattern fully matches the action."""
    if rule.event_action_re is None:
        return False
    return rule.event_action_re.fullmatch(_bounded(event_action or "")) is not None


def _strict_tier_for_rule(
    rule: MappingRule, event: LogEvent, lowered_extensions: Mapping[str, Any]
) -> Optional[int]:
    """Return the tier (1 or 2) at which a non-heuristic rule matches, else None.

    Rules declaring extension keys can only match at tier 1; rules without
    extension keys can only match at tier 2 via their action pattern.
    A rule's declared action pattern (if any) must ALSO pass at tier 1 -
    ext_keys scope *which* field to inspect, the action pattern scopes
    *which event* the rule applies to. Without this, an exists-style rule
    like M010 (user_account_created + targetusername) would fire on every
    logon event carrying a TargetUserName field.
    """
    if len(rule.ext_keys) > 0:
        if _extension_checks_pass(rule, lowered_extensions) and (
            rule.event_action_re is None
            or _action_check_passes(rule, event.event_action)
        ):
            return 1
        return None
    if _action_check_passes(rule, event.event_action):
        return 2
    return None


def _heuristic_checks_pass(
    rule: MappingRule, event: LogEvent, lowered_extensions: Mapping[str, Any]
) -> bool:
    """Return whether a heuristic rule's declared checks all pass.

    Extension keys (if declared) and the action pattern (if declared) must
    both pass; a heuristic declaring neither passes vacuously as a pure
    format-level prior.
    """
    if len(rule.ext_keys) > 0 and not _extension_checks_pass(rule, lowered_extensions):
        return False
    if rule.event_action_re is not None and not _action_check_passes(
        rule, event.event_action
    ):
        return False
    return True


def _record_match(
    matches: Dict[str, Any], rule: MappingRule, score: float
) -> None:
    """Record a match, keeping only the highest-scoring rule per technique."""
    current = matches.get(rule.technique_id)
    if current is None or score > current[0]:
        matches[rule.technique_id] = (score, rule)
