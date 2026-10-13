"""Remediation analysis for coverage gaps (Phase 7).

Derives remediation categories and candidate-source details from existing
coverage evidence and collection inventory. Pure analysis layer: no I/O,
no DB mutations.

Frozen contracts:
- ``Gap.closable_by``: disabled sources whose static projection reaches
  the detection threshold.
- ``CoverageRow.source_ids``: enabled sources contributing evidence.
- ``CoverageRow.best_confidence``: technique-level best confidence across
  enabled sources.
- ``collected_log_sources`` from config: None=unknown, frozenset()=empty,
  frozenset([...])=declared inventory.

Remediation categories are derived, not stored. Every gap retains all
candidate-source options so the dashboard can present alternatives.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Literal

from src.analysis.coverage_analyzer import (
    CoverageRow,
    Gap,
    _mapping_sources_for,  # canonical mapper eligibility
)
from src.config_loader import CollectedSources


class RemediationCategory(Enum):
    """Primary remediation grouping for a gap."""

    # Non-empty closable_by
    CANDIDATE_SOURCE_ENABLEMENT = "candidate_source_enablement"
    POTENTIAL_SOURCE_ACQUISITION = "potential_source_acquisition"
    SOURCE_STATUS_UNKNOWN = "source_status_unknown"

    # Empty closable_by
    REVIEW_EXISTING_SOURCE_MAPPINGS = "review_existing_source_mappings"
    MAPPING_TELEMETRY_REVIEW = "mapping_telemetry_review"
    MAPPING_COVERAGE_GAP = "mapping_coverage_gap"

    # Data quality
    DATA_QUALITY_ISSUE = "data_quality_issue"


SourceStatus = Literal[
    "collected_disabled",
    "not_collected",
    "unknown_status",
    "validation_error",
]

ActionType = Literal[
    "enable",
    "acquire",
    "investigate_status",
    "investigate",
]


@dataclass(frozen=True)
class CandidateSourceStatus:
    """One candidate source with its collection status and potential action."""

    source: str
    status: SourceStatus
    action: ActionType


@dataclass(frozen=True)
class RemediationDetail:
    """Complete remediation detail for one gap."""

    gap: Gap
    primary_category: RemediationCategory
    candidate_sources: tuple[CandidateSourceStatus, ...]
    enabled_source_evidence: tuple[int, ...]
    enabled_mapping_sources: tuple[str, ...]
    all_mapping_sources: tuple[str, ...]
    validation_errors: tuple[str, ...]


def classify_remediation(
    gap: Gap,
    coverage_row: CoverageRow,
    enabled_sources: frozenset[str],
    collected_sources: CollectedSources,
    all_rules_by_source: dict[str, list],
    threshold: float,
) -> RemediationDetail:
    """Derive remediation detail for one gap.

    Builds candidate-source statuses individually so every option is preserved.
    Validation errors (enabled source in closable_by) are detected first and
    block normal classification, but candidate details are still preserved.

    Args:
        gap: The coverage gap.
        coverage_row: The corresponding CoverageRow with source evidence.
        enabled_sources: Currently enabled log sources.
        collected_sources: Collection inventory (None=unknown, frozenset()=empty).
        all_rules_by_source: Mapping rules keyed by source format.
        threshold: Detection confidence threshold.

    Returns:
        RemediationDetail with primary category and full candidate details.
    """
    # 0. Validation: enabled source in closable_by (invariant violation)
    validation_errors = tuple(
        src for src in gap.closable_by if src in enabled_sources
    )

    # Build candidate sources individually (preserve all options)
    candidates = []
    for src in gap.closable_by:
        if src in enabled_sources:
            # Invariant violation: enabled source in closable_by
            candidates.append(
                CandidateSourceStatus(
                    source=src,
                    status="validation_error",
                    action="investigate",
                )
            )
        elif collected_sources is None:
            candidates.append(
                CandidateSourceStatus(
                    source=src,
                    status="unknown_status",
                    action="investigate_status",
                )
            )
        elif src in collected_sources:
            candidates.append(
                CandidateSourceStatus(
                    source=src,
                    status="collected_disabled",
                    action="enable",
                )
            )
        else:
            candidates.append(
                CandidateSourceStatus(
                    source=src,
                    status="not_collected",
                    action="acquire",
                )
            )

    if validation_errors:
        return RemediationDetail(
            gap=gap,
            primary_category=RemediationCategory.DATA_QUALITY_ISSUE,
            candidate_sources=tuple(candidates),
            enabled_source_evidence=coverage_row.source_ids if coverage_row else (),
            enabled_mapping_sources=(),
            all_mapping_sources=(),
            validation_errors=validation_errors,
        )

    # Mapping sources
    enabled_mapping_srcs = _mapping_sources_for(
        gap.technique_attack_id, enabled_sources, all_rules_by_source
    )
    all_mapping_srcs = _mapping_sources_for(
        gap.technique_attack_id,
        frozenset(all_rules_by_source.keys()),
        all_rules_by_source,
    )

    # 1. Non-empty closable_by: candidate source enablement/acquisition
    if candidates:
        has_enablement = any(c.status == "collected_disabled" for c in candidates)
        has_acquisition = any(c.status == "not_collected" for c in candidates)
        has_unknown = any(c.status == "unknown_status" for c in candidates)

        if has_enablement:
            primary = RemediationCategory.CANDIDATE_SOURCE_ENABLEMENT
        elif has_acquisition:
            primary = RemediationCategory.POTENTIAL_SOURCE_ACQUISITION
        elif has_unknown:
            primary = RemediationCategory.SOURCE_STATUS_UNKNOWN
        else:
            # Should not reach here unless validation_error (handled above)
            primary = RemediationCategory.DATA_QUALITY_ISSUE

        return RemediationDetail(
            gap=gap,
            primary_category=primary,
            candidate_sources=tuple(candidates),
            enabled_source_evidence=coverage_row.source_ids if coverage_row else (),
            enabled_mapping_sources=enabled_mapping_srcs,
            all_mapping_sources=all_mapping_srcs,
            validation_errors=(),
        )

    # 2. Empty closable_by: no candidate source reaches threshold
    # 2a. Existing-source mapping review: enabled source contributes but < threshold
    if coverage_row and coverage_row.source_ids and coverage_row.best_confidence < threshold:
        primary = RemediationCategory.REVIEW_EXISTING_SOURCE_MAPPINGS

    # 2b. Mapping/telemetry review: mappings exist in enabled sources
    elif enabled_mapping_srcs:
        primary = RemediationCategory.MAPPING_TELEMETRY_REVIEW

    # 2c. Mappings exist elsewhere but no candidate reaches threshold
    elif _mapping_sources_for(
        gap.technique_attack_id,
        frozenset(all_rules_by_source.keys()),
        all_rules_by_source,
    ):
        primary = RemediationCategory.MAPPING_TELEMETRY_REVIEW

    # 2d. True mapping coverage gap
    else:
        primary = RemediationCategory.MAPPING_COVERAGE_GAP

    return RemediationDetail(
        gap=gap,
        primary_category=primary,
        candidate_sources=(),
        enabled_source_evidence=coverage_row.source_ids if coverage_row else (),
        enabled_mapping_sources=enabled_mapping_srcs,
        all_mapping_sources=all_mapping_srcs,
        validation_errors=(),
    )


def classify_all_gaps(
    gaps: tuple[Gap, ...],
    coverage_rows: list[CoverageRow],
    enabled_sources: frozenset[str],
    collected_sources: CollectedSources,
    all_rules_by_source: dict[str, list],
    threshold: float,
) -> tuple[RemediationDetail, ...]:
    """Classify all gaps in bulk.

    Args:
        gaps: All gaps from calculate_coverage_gaps.
        coverage_rows: Corresponding coverage rows (matched by technique_attack_id).
        enabled_sources: Currently enabled sources.
        collected_sources: Collection inventory.
        all_rules_by_source: All mapping rules by source.
        threshold: Detection threshold.

    Returns:
        RemediationDetail tuple in same order as input gaps.
    """
    # Build coverage row lookup
    cov_by_tech = {row.attack_id: row for row in coverage_rows}
    return tuple(
        classify_remediation(
            gap=gap,
            coverage_row=cov_by_tech.get(gap.technique_attack_id),
            enabled_sources=enabled_sources,
            collected_sources=collected_sources,
            all_rules_by_source=all_rules_by_source,
            threshold=threshold,
        )
        for gap in gaps
    )


# Back-compat: re-export canonical _mapping_sources_for
from src.analysis.coverage_analyzer import _mapping_sources_for as _mapping_sources_for