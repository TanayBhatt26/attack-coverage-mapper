"""Analysis layer for ATT&CK Coverage Mapper.

Public entry points:

- :mod:`analysis.coverage_analyzer` -- coverage rows, tactic rollup, gaps.
- :mod:`analysis.gap_clustering` -- KMeans clustering of gaps.
- :mod:`analysis.simulation` -- APT simulation + recommendations.
- :mod:`analysis.remediation` -- gap remediation classification (Phase 7).
"""

from .coverage_analyzer import (
    load_coverage_rows,
    coverage_by_tactic,
    calculate_coverage_gaps,
    build_closable_index,
    _mapping_sources_for,
    CoverageRow,
    Gap,
    TacticCoverage,
)

from .gap_clustering import (
    cluster_gaps,
    GapItem,
    GapCluster,
    ClusteringParams,
)

from .simulation import (
    simulate_apt_attack,
    generate_recommendations,
    list_apt_groups,
    resolve_apt_group,
    SimulationOutcome,
    TechniqueOutcome,
    TacticBreakdown,
)

from .remediation import (
    classify_remediation,
    classify_all_gaps,
    RemediationDetail,
    RemediationCategory,
    CandidateSourceStatus,
    _mapping_sources_for,
)

__all__ = [
    "load_coverage_rows",
    "coverage_by_tactic",
    "calculate_coverage_gaps",
    "build_closable_index",
    "_mapping_sources_for",
    "cluster_gaps",
    "GapItem",
    "GapCluster",
    "ClusteringParams",
    "simulate_apt_attack",
    "generate_recommendations",
    "list_apt_groups",
    "resolve_apt_group",
    "SimulationOutcome",
    "TechniqueOutcome",
    "TacticBreakdown",
    "classify_remediation",
    "classify_all_gaps",
    "RemediationDetail",
    "RemediationCategory",
    "CandidateSourceStatus",
    "_mapping_sources_for",
    "CoverageRow",
    "Gap",
    "TacticCoverage",
]