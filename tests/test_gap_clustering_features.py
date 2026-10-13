"""Tests for ``analysis.gap_clustering`` -- feature construction and clustering policy.

Scope of this module (Phase 3, Wave 2 deliverable ``tests/test_gap_clustering_features.py``):

* **Contract surface** (Wave-1 empirical findings, ``research/p3-wave1-full-results.md``
  and ``research/swarm2-planning-designs.md``):
  - ``GapItem(technique_attack_id, name, tactic, description)`` -- frozen, hashable,
    primitive/tuple fields only (contract A hashability).
  - ``GapCluster(cluster_id, label, technique_ids, summary, size)`` -- frozen,
    hashable; ``cluster_gaps`` returns a plain ``tuple`` of them.
  - ``ClusteringParams`` mirrors the optional top-level ``clustering`` config section
    (contract H defaults: ``min_clusterable=4, k_max=6, silhouette_threshold=0.2,
    max_vocab=200, seed=42``) with ``ValueError`` validation.
  - Features: a 14-dimensional tactic one-hot block scaled ``w=2.0`` in canonical
    ATT&CK order, concatenated with TF-IDF over ``"{name} {description}"``
    (lowercase ``[a-z0-9]{3,}`` tokens, sublinear tf, L2-normalised rows, stopword
    set including ``technique/adversaries/may/using/windows/attack/system``,
    vocabulary capped at ``max_vocab``).
  - Policy: ``n == 0`` -> ``()``; ``n <= min_clusterable`` -> single cluster, no
    model fitted; otherwise k swept over ``range(2, min(k_max, n // 2) + 1)``,
    best mean silhouette wins (ties favour smaller k); a split is accepted iff
    ``silhouette >= 0.20`` **and** every cluster holds ``size >= 2``; NaN
    silhouette falls back to a single cluster.
  - Labels follow ``"{majority tactic}: {kw1}/{kw2}"`` where keywords maximise
    ``mean(tfidf inside) - mean(tfidf outside)`` above ``0.05``; summaries are one
    sentence starting with ``"{n} undetected techniques"``.
  - Determinism: identical inputs and params reproduce identical outputs (seeded).
    True cross-process spawning needs ``subprocess``, which this suite forbids;
    repeat-call determinism within the process is verified instead.

* **Golden regression**: the real-world current gap set (~449 Windows-scoped gaps)
  measured ``max silhouette ~= 0.168`` across ``k=2..6`` (agent-185,
  ``research/p3-wave1-full-results.md``), below the 0.20 gate, so the policy must
  conservatively return ONE cluster. A seeded 449-item synthetic set mimicking the
  lopsided, fuzzy real distribution is asserted to collapse the same way.

Feature-level unit tests drive the module's ``_build_feature_matrix`` helper
directly: the contract pins feature *semantics*, not a public builder name, and
this private helper is the only precise window onto them. Controlled corpora pass
``name=""`` so the featurised document is exactly the description under test.

Everything here is offline and pure-function (no filesystem, no DB, no network);
the module is marked ``unit`` accordingly.
"""

from __future__ import annotations

import logging
import random
import re
from dataclasses import FrozenInstanceError, fields as dataclass_fields
from typing import Any, Callable, Sequence

import numpy as np
import pytest

import analysis.gap_clustering as gap_clustering_module
from analysis.gap_clustering import (
    CANONICAL_TACTICS,
    ClusteringParams,
    GapCluster,
    GapItem,
    cluster_gaps,
)

logger = logging.getLogger(__name__)

#: Pure-function tests: no I/O of any kind.
pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Stopwords the TF-IDF stage must drop (contract-named minimum set).
CONTRACT_STOPWORDS: tuple[str, ...] = (
    "technique",
    "adversaries",
    "may",
    "using",
    "windows",
    "attack",
    "system",
)

#: Private feature-matrix builder on the implementation module. Kept in a tuple
#: so the skipif marker degrades gracefully if the helper is ever renamed.
_FEATURE_BUILDER_NAMES: tuple[str, ...] = ("_build_feature_matrix",)


# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------

def make_params(**overrides: Any) -> ClusteringParams:
    """Build :class:`ClusteringParams` with the documented defaults overridden."""
    values: dict[str, Any] = {
        "min_clusterable": 4,
        "k_max": 6,
        "silhouette_threshold": 0.2,
        "max_vocab": 200,
        "seed": 42,
    }
    values.update(overrides)
    return ClusteringParams(**values)


def make_gap(
    technique_attack_id: str,
    tactic: str,
    description: str,
    name: str | None = None,
) -> GapItem:
    """Construct a :class:`GapItem`; ``name=None`` keeps the realistic default."""
    return GapItem(
        technique_attack_id=technique_attack_id,
        name=name if name is not None else f"Technique {technique_attack_id}",
        tactic=tactic,
        description=description,
    )


def _find_feature_builder() -> Callable[..., Any] | None:
    """Locate the module's feature-matrix builder (private, stable signature)."""
    for attr in _FEATURE_BUILDER_NAMES:
        candidate = getattr(gap_clustering_module, attr, None)
        if callable(candidate):
            return candidate
    return None


#: Marker for feature-level tests: skipped only if the private helper vanishes.
requires_feature_builder = pytest.mark.skipif(
    _find_feature_builder() is None,
    reason=(
        "gap_clustering exposes no _build_feature_matrix helper; feature "
        "semantics are then only covered indirectly through cluster_gaps"
    ),
)


def _as_matrix(builder_result: Any) -> np.ndarray:
    """Normalise a builder return value into a 2-D float ndarray.

    Tolerates ``(matrix, vocabulary)`` tuples by taking the first element.
    """
    if isinstance(builder_result, tuple) and len(builder_result) >= 1:
        builder_result = builder_result[0]
    matrix = np.asarray(builder_result, dtype=float)
    if matrix.ndim != 2:
        raise AssertionError(
            f"feature builder returned {matrix.ndim}-D output, expected 2-D"
        )
    return matrix


def _self_normalized(row: np.ndarray) -> np.ndarray:
    """Return *row* scaled to unit L2 norm (zero rows pass through)."""
    norm = float(np.linalg.norm(row))
    return row / norm if norm > 0.0 else row


# ---------------------------------------------------------------------------
# Synthetic corpora
# ---------------------------------------------------------------------------
# Theme vocabularies are deliberately pairwise disjoint (guarded at import) so
# distinguishing-keyword scores separate cleanly. Each theme combines a fixed
# core phrase (present in every member -> strong distinguishing scores), a
# rotation phrase (varies within the theme -> member vectors are not exact
# duplicates), and a filler phrase.

_CRED_CORE = "kerberos ntlm credential dumping password extraction"
_CRED_ROTATION = ("lsass mimikatz", "golden ticket forged", "brute force spray")
_CRED_FILLER = (
    "domain controller authentication",
    "active directory environment",
    "account manipulation abuse",
)
_CRED_TOKENS = frozenset(
    _CRED_CORE.split()
    + " ".join(_CRED_ROTATION).split()
    + " ".join(_CRED_FILLER).split()
)

_PERS_CORE = "registry run key modification scheduled task installation"
_PERS_ROTATION = ("dll loading autorun", "startup folder shortcut", "browser extension hijack")
_PERS_FILLER = (
    "boot autostart mechanism",
    "office template macro",
    "hidden attribute files",
)
_PERS_TOKENS = frozenset(
    _PERS_CORE.split()
    + " ".join(_PERS_ROTATION).split()
    + " ".join(_PERS_FILLER).split()
)

_EXFIL_CORE = "dns tunneling exfiltration encrypted channel backup upload"
_EXFIL_ROTATION = ("cloud storage staging", "alternate protocol material", "bulk copying transfer")
_EXFIL_FILLER = (
    "periodic egress windows",
    "web portal beaconing",
    "archive compression packing",
)
_EXFIL_TOKENS = frozenset(
    _EXFIL_CORE.split()
    + " ".join(_EXFIL_ROTATION).split()
    + " ".join(_EXFIL_FILLER).split()
)

_DISC_CORE = "network service discovery remote shares enumeration"
_DISC_ROTATION = ("probe sweep scan", "connected devices survey", "permission groups inventory")
_DISC_FILLER = (
    "shared resources locate",
    "running instances fingerprint",
    "trust relationships chart",
)
_DISC_TOKENS = frozenset(
    _DISC_CORE.split()
    + " ".join(_DISC_ROTATION).split()
    + " ".join(_DISC_FILLER).split()
)

_THEME_SPECS: tuple[tuple[str, str, tuple[str, ...], tuple[str, ...], frozenset[str]], ...] = (
    ("credential-access", _CRED_CORE, _CRED_ROTATION, _CRED_FILLER, _CRED_TOKENS),
    ("persistence", _PERS_CORE, _PERS_ROTATION, _PERS_FILLER, _PERS_TOKENS),
    ("exfiltration", _EXFIL_CORE, _EXFIL_ROTATION, _EXFIL_FILLER, _EXFIL_TOKENS),
)
_FOUR_THEME_SPECS = _THEME_SPECS + (
    ("discovery", _DISC_CORE, _DISC_ROTATION, _DISC_FILLER, _DISC_TOKENS),
)
_THEME_TOKENS_BY_TACTIC: dict[str, frozenset[str]] = {
    spec[0]: spec[4] for spec in _FOUR_THEME_SPECS
}


def _assert_themes_disjoint() -> None:
    """Guard against accidental vocabulary overlap between synthetic themes."""
    seen: dict[str, str] = {}
    for tactic, _, _, _, tokens in _FOUR_THEME_SPECS:
        for token in tokens:
            if token in seen and seen[token] != tactic:
                raise AssertionError(
                    f"token {token!r} appears in themes {seen[token]!r} and {tactic!r}"
                )
            seen[token] = tactic


_assert_themes_disjoint()


def themed_gaps(
    items_per_theme: int = 6,
    specs: Sequence[Any] = _THEME_SPECS,
) -> list[GapItem]:
    """Build keyword-disjoint, per-theme coherent gap items with unique ids."""
    gaps: list[GapItem] = []
    counter = 0
    for tactic, core, rotation, filler, _tokens in specs:
        for i in range(items_per_theme):
            counter += 1
            description = (
                f"{core} {rotation[i % len(rotation)]} {filler[(i // 2) % len(filler)]}"
            )
            gaps.append(
                make_gap(
                    f"T{counter:04d}",
                    tactic,
                    description,
                    name=f"{tactic} variant {counter}",
                )
            )
    return gaps


# ---------------------------------------------------------------------------
# Contract surface: types, freezing, hashing
# ---------------------------------------------------------------------------

class TestContractSurface:
    """GapItem / GapCluster dataclass contracts and cluster_gaps typing."""

    def test_dataclass_field_names_match_contract(self) -> None:
        """Both frozen dataclasses expose exactly the contracted fields."""
        assert {f.name for f in dataclass_fields(GapItem)} == {
            "technique_attack_id",
            "name",
            "tactic",
            "description",
        }
        assert {f.name for f in dataclass_fields(GapCluster)} == {
            "cluster_id",
            "label",
            "technique_ids",
            "summary",
            "size",
        }

    def test_canonical_tactic_order_exported_and_correct(self) -> None:
        """The module's canonical order equals the ATT&CK kill-chain order."""
        assert CANONICAL_TACTICS == (
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

    def test_gapitem_is_frozen_and_hashable(self) -> None:
        """GapItem rejects mutation and supports hashing / set membership."""
        item = make_gap("T1001", "execution", "command interpreter payload")
        with pytest.raises(FrozenInstanceError):
            item.tactic = "persistence"  # type: ignore[misc]
        assert isinstance(hash(item), int)
        twin = make_gap("T1001", "execution", "command interpreter payload")
        assert len({item, twin}) == 1, "equal-value items should collapse in a set"

    def test_clusters_are_frozen_hashable_tuples(self) -> None:
        """cluster_gaps returns a tuple of frozen, hashable GapCluster objects."""
        clusters = cluster_gaps(themed_gaps(), make_params())
        assert isinstance(clusters, tuple)
        assert all(isinstance(cluster, GapCluster) for cluster in clusters)
        for cluster in clusters:
            with pytest.raises(FrozenInstanceError):
                cluster.label = "mutated"  # type: ignore[misc]
            assert isinstance(hash(cluster), int)
            assert isinstance(cluster.technique_ids, tuple)

    def test_cluster_bookkeeping_fields_consistent(self) -> None:
        """size mirrors technique_ids length; cluster_id forms 0..k-1 permutation."""
        clusters = cluster_gaps(themed_gaps(), make_params())
        assert sorted(c.cluster_id for c in clusters) == list(range(len(clusters)))
        for cluster in clusters:
            assert cluster.size == len(cluster.technique_ids)
            assert cluster.size >= 1
            assert cluster.label
            assert cluster.summary

    def test_input_type_validation(self) -> None:
        """Non-GapItem elements and non-ClusteringParams params are TypeErrors."""
        with pytest.raises(TypeError):
            cluster_gaps(["not-a-gap"], make_params())  # type: ignore[list-item]
        with pytest.raises(TypeError):
            cluster_gaps([], {"clustering": {}})  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# ClusteringParams config bridge (contract H defaults and validation)
# ---------------------------------------------------------------------------

class TestClusteringParamsConfigBridge:
    """Defaults, overrides, and ValueError validation on the config mapping."""

    def test_defaults_when_section_absent_or_empty(self) -> None:
        """None and {} both yield the documented default parameter set."""
        expected = ClusteringParams(
            min_clusterable=4,
            k_max=6,
            silhouette_threshold=0.2,
            max_vocab=200,
            seed=42,
        )
        assert ClusteringParams.from_config(None) == expected
        assert ClusteringParams.from_config({}) == expected

    def test_known_overrides_applied(self) -> None:
        """Provided keys override; omitted keys keep defaults."""
        params = ClusteringParams.from_config({"seed": 7, "k_max": 3})
        assert params.seed == 7
        assert params.k_max == 3
        assert params.min_clusterable == 4
        assert params.silhouette_threshold == 0.2
        assert params.max_vocab == 200

    def test_unknown_keys_logged_and_ignored(self) -> None:
        """Forward compatibility: unknown keys never raise."""
        params = ClusteringParams.from_config({"future_knob": "x"})
        assert params == ClusteringParams.from_config(None)

    @pytest.mark.parametrize("bad", [{"min_clusterable": "four"}, {"k_max": True},
                                     {"max_vocab": 0}, {"k_max": 1}, {"seed": -1},
                                     {"seed": 2**32}])
    def test_bad_int_values_raise_value_error(self, bad: dict[str, Any]) -> None:
        """Wrong types (bools included) and out-of-range ints raise ValueError."""
        with pytest.raises(ValueError):
            ClusteringParams.from_config(bad)

    @pytest.mark.parametrize("threshold", [0, -0.5, 1.5, "high"])
    def test_bad_silhouette_threshold_raises_value_error(
        self, threshold: Any
    ) -> None:
        """Threshold must be a number strictly above zero and at most one."""
        with pytest.raises(ValueError):
            ClusteringParams.from_config({"silhouette_threshold": threshold})


# ---------------------------------------------------------------------------
# Policy branches
# ---------------------------------------------------------------------------

class TestPolicyBranches:
    """Empty / small-n / fallback / acceptance branches of the k-selection policy."""

    @pytest.mark.parametrize(
        "params",
        [make_params(), make_params(seed=7), None],
        ids=["default", "alt-seed", "none-defaults"],
    )
    def test_empty_input_returns_empty_tuple(
        self, params: ClusteringParams | None
    ) -> None:
        """n == 0 gracefully yields (), whatever (valid) params are supplied."""
        result = cluster_gaps([], params)
        assert result == ()
        assert isinstance(result, tuple)

    @pytest.mark.parametrize("n", [1, 2, 3])
    def test_small_inputs_yield_single_cluster_without_kmeans(self, n: int) -> None:
        """n <= min_clusterable collapses to one cluster holding every input id.

        Items are deliberately maximally diverse (different tactics, disjoint
        vocabulary): a buggy implementation that ran KMeans on tiny n could
        split them; the policy must never try.
        """
        items = [
            make_gap("T0001", "credential-access", "kerberos ntlm credential dumping"),
            make_gap("T0002", "exfiltration", "dns tunneling exfiltration channel"),
            make_gap("T0003", "discovery", "network shares enumeration probe"),
        ][:n]
        clusters = cluster_gaps(items, make_params())
        assert len(clusters) == 1
        only = clusters[0]
        assert only.size == n
        assert set(only.technique_ids) == {g.technique_attack_id for g in items}

    def test_accepts_sequence_inputs_not_only_lists(self) -> None:
        """Any Iterable/Sequence (e.g. a tuple) is a valid input container."""
        listed = cluster_gaps(themed_gaps(), make_params())
        tupled = cluster_gaps(tuple(themed_gaps()), make_params())
        assert [repr(c) for c in listed] == [repr(c) for c in tupled]

    def test_identical_items_nan_silhouette_falls_back(self) -> None:
        """Duplicate feature vectors make the silhouette degenerate -> fallback.

        Six items identical except for their technique ids produce byte-equal
        rows; whether the backend yields NaN or a degenerate optimum, the only
        conforming outcome is the conservative single-cluster fallback.
        """
        clones = [
            make_gap(f"T{i}", "defense-evasion", "process injection api misuse", name="")
            for i in range(6)
        ]
        clusters = cluster_gaps(clones, make_params())
        assert len(clusters) == 1
        assert clusters[0].size == 6
        assert set(clusters[0].technique_ids) == {c.technique_attack_id for c in clones}

    def test_singleton_split_rejected_by_min_size_guard(self) -> None:
        """A 4+1 dataset can only split 4/1 -> size guard forces fallback.

        Four coincident points plus one distant outlier: k is confined to
        range(2, min(6, 5 // 2) + 1) = {2}, whose inertia-optimum isolates the
        outlier (splitting the identical blob cannot reduce inertia). The
        resulting singleton cluster must trip the min-size >= 2 guard.
        """
        blob = [
            make_gap(f"T{i}", "persistence", "registry run key modification", name="")
            for i in range(4)
        ]
        outsider = make_gap("T9000", "reconnaissance", "spearphishing victim compromise", name="")
        clusters = cluster_gaps(blob + [outsider], make_params())
        assert len(clusters) == 1
        assert clusters[0].size == 5

    def test_disjoint_themes_accept_three_clusters(self) -> None:
        """Three keyword-disjoint themes -> exactly 3 clusters, pure membership."""
        items = themed_gaps(items_per_theme=6)
        clusters = cluster_gaps(items, make_params())
        assert len(clusters) == 3

        id_to_item = {g.technique_attack_id: g for g in items}
        covered: set[str] = set()
        for cluster in clusters:
            members = [id_to_item[tid] for tid in cluster.technique_ids]
            tactics = {m.tactic for m in members}
            assert len(tactics) == 1, f"impure cluster {cluster.label}: {tactics}"
            assert next(iter(tactics)) in cluster.label
            covered.update(cluster.technique_ids)
        assert covered == set(id_to_item), "union of clusters must cover all inputs"

    def test_union_disjointness_invariant(self) -> None:
        """Technique ids across clusters are pairwise disjoint and complete."""
        items = themed_gaps(items_per_theme=5)
        clusters = cluster_gaps(items, make_params())
        all_ids: list[str] = []
        for cluster in clusters:
            all_ids.extend(cluster.technique_ids)
        assert len(all_ids) == len(set(all_ids))
        assert set(all_ids) == {g.technique_attack_id for g in items}

    def test_high_silhouette_threshold_forces_single_cluster(self) -> None:
        """threshold=0.999 is unreachable -> policy falls back to one cluster."""
        items = themed_gaps(items_per_theme=6)
        clusters = cluster_gaps(items, make_params(silhouette_threshold=0.999))
        assert len(clusters) == 1
        assert clusters[0].size == len(items)

    def test_low_min_clusterable_gate_controls_kmeans_invocation(self) -> None:
        """Raising min_clusterable above n disables KMeans even for separable data.

        5 items in a clean 3+2 split: the default policy sweeps k=2 and accepts;
        raising ``min_clusterable`` to 6 must short-circuit to the single
        cluster without fitting any model.
        """
        credential_side = themed_gaps(items_per_theme=3)[:3]
        # Second generator call re-uses serials T0001..; pick its exfil pair
        # (T0005/T0006) so ids stay disjoint from the credential trio.
        exfil_side = [
            gap for gap in themed_gaps(items_per_theme=2) if gap.tactic == "exfiltration"
        ]
        items = credential_side + exfil_side
        assert len(items) == 5
        assert len({g.technique_attack_id for g in items}) == 5

        default_run = cluster_gaps(items, make_params())
        guarded_run = cluster_gaps(items, make_params(min_clusterable=6))
        assert len(default_run) == 2
        assert len(guarded_run) == 1
        assert guarded_run[0].size == 5

    def test_k_max_caps_the_sweep_upper_bound(self) -> None:
        """k_max=2 restricts the sweep so fewer clusters emerge than default.

        Four well-separated themes admit k=4 under the default sweep; clamping
        ``k_max`` to 2 forbids any partition finer than two meta-clusters.
        """
        items = themed_gaps(items_per_theme=5, specs=_FOUR_THEME_SPECS)
        default_run = cluster_gaps(items, make_params())
        capped_run = cluster_gaps(items, make_params(k_max=2))
        assert len(default_run) >= 3
        assert 1 <= len(capped_run) <= 2
        assert len(capped_run) < len(default_run)


# ---------------------------------------------------------------------------
# Labels and summaries
# ---------------------------------------------------------------------------

class TestLabelsAndSummaries:
    """Label grammar '{majority tactic}: kw1/kw2' and one-sentence summaries."""

    _LABEL_RE = re.compile(r"^([a-z][a-z0-9-]*):\s*(.+)$")

    def _clusters(self) -> tuple[list[GapCluster], dict[str, GapItem]]:
        items = themed_gaps(items_per_theme=6)
        clusters = cluster_gaps(items, make_params())
        assert len(clusters) == 3, "precondition: themes must separate for label checks"
        return list(clusters), {g.technique_attack_id: g for g in items}

    def test_label_matches_tactic_prefix_grammar(self) -> None:
        """Every label parses as '<majority tactic>: <keywords>'."""
        clusters, id_to_item = self._clusters()
        for cluster in clusters:
            match = self._LABEL_RE.match(cluster.label)
            assert match is not None, f"label {cluster.label!r} lacks 'tactic: keywords'"
            member_tactics = {id_to_item[t].tactic for t in cluster.technique_ids}
            assert match.group(1) in member_tactics

    def test_label_keywords_drawn_from_theme_vocabulary(self) -> None:
        """Distinguishing keywords belong to the cluster's own theme tokens."""
        clusters, id_to_item = self._clusters()
        token_re = re.compile(r"[a-z0-9]{3,}")
        for cluster in clusters:
            members = [id_to_item[t] for t in cluster.technique_ids]
            tactic = members[0].tactic
            theme = _THEME_TOKENS_BY_TACTIC[tactic]
            label_tokens = set(token_re.findall(cluster.label.lower()))
            label_tokens.discard(tactic)
            assert label_tokens & theme, (
                f"label {cluster.label!r} carries no {tactic} theme keyword"
            )

    def test_summary_is_one_sentence_with_counts_and_slash(self) -> None:
        """Summaries start '<n> undetected techniques', contain '/', end '.'."""
        clusters, _ = self._clusters()
        for cluster in clusters:
            summary = cluster.summary
            assert summary.startswith(f"{cluster.size} undetected techniques")
            assert "/" in summary, "summary should juxtapose kw1/kw2"
            assert summary.endswith(".")
            assert "\n" not in summary

    def test_summary_mentions_dominant_tactic(self) -> None:
        """The cluster's majority tactic surfaces in its summary text."""
        clusters, id_to_item = self._clusters()
        for cluster in clusters:
            tactics = {id_to_item[t].tactic for t in cluster.technique_ids}
            assert len(tactics) == 1
            assert next(iter(tactics)) in cluster.summary


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

class TestDeterminism:
    """Seeded reproducibility: identical inputs -> identical outputs."""

    @pytest.mark.parametrize("seed", [42, 7])
    def test_repeat_calls_byte_identical(self, seed: int) -> None:
        """Two calls with equal params produce repr-identical cluster tuples."""
        items = themed_gaps(items_per_theme=6)
        first = cluster_gaps(items, make_params(seed=seed))
        second = cluster_gaps(items, make_params(seed=seed))
        assert [repr(c) for c in first] == [repr(c) for c in second]

    def test_homogeneous_fallback_stable_across_calls(self) -> None:
        """The fallback path is equally deterministic (single 12-item cluster)."""
        items = [
            make_gap(
                f"T{i}",
                "defense-evasion",
                "obfuscated script interpreter payload execution trace",
                name="",
            )
            for i in range(12)
        ]
        first = cluster_gaps(items, make_params())
        second = cluster_gaps(items, make_params())
        assert [repr(c) for c in first] == [repr(c) for c in second]
        assert len(first) == 1 and first[0].size == 12


# ---------------------------------------------------------------------------
# Golden regression: the ~449-gap real-world mass collapses to ONE cluster
# ---------------------------------------------------------------------------

class TestRealisticMassRegression:
    """Golden regression for the Wave-1 verdict on the production-scale mass.

    Agent-185 (``research/p3-wave1-full-results.md``) measured the real
    449-gap Windows-scoped set at best mean silhouette ~0.168 over k=2..6 --
    below the 0.20 gate, so ``cluster_gaps`` must conservatively return a
    SINGLE 449-item cluster. Empirically (this suite's probes) that outcome is
    structural: with tactic one-hot weight w=2.0 any differently-tagged pair
    sits at euclidean distance >= 2*sqrt(2) while same-tag pairs stay within
    sqrt(2), so a mass whose tactics are *uniform or degraded* -- exactly the
    tag regime the Wave-1 data was measured in, and the v19 phase-aliasing bug
    documented in contract G -- presents no exploitable structure and collapses
    (this generator measures s ~= 0.016). Conversely, a fully tagged
    multi-tactic mass of the same size legitimately separates; both facets are
    pinned so neither "always split" nor "never split" regressions can land.
    """

    _SHARED_VOCABULARY: tuple[str, ...] = (
        "process injection api memory script interpreter payload shellcode",
        "network connection domain encryption obfuscation registry hive token",
        "privileges escalation service creation scheduled persistence startup",
        "proxy tunnel port scanning session hijack credential dumping hash",
        "capture screenshot keylog clipboard email attachment macro document",
        "exploit vulnerability remote desktop share drive file transfer archive",
        "staging compression exfil channel beacon interval jitter webhook",
        "query record certificate signing binary sideload loader dropper",
        "downloader watchdog mutex sandbox evasion tracing debugger account",
    )

    #: Uniform tactic signature of the collapsed mass (any canonical value
    #: behaves identically: the one-hot block becomes a constant column).
    _UNIFORM_TACTIC = "defense-evasion"

    #: Lopsided but genuinely tagged composition proving separation still works
    #: when real tactic structure exists (sums to 449).
    _MULTI_TACTIC_COUNTS: tuple[tuple[str, int], ...] = (
        ("defense-evasion", 260),
        ("execution", 80),
        ("persistence", 40),
        ("credential-access", 25),
        ("discovery", 15),
        ("lateral-movement", 10),
        ("collection", 6),
        ("command-and-control", 5),
        ("exfiltration", 3),
        ("impact", 3),
        ("initial-access", 1),
        ("privilege-escalation", 1),
    )

    _MASS_SEED = 20260826

    def _mass_gaps(
        self, plan: Sequence[tuple[str, int]] | None = None
    ) -> list[GapItem]:
        """Generate the seeded 449-item gap mass (uniform or per-plan tags).

        Descriptions sample 8-12 tokens from one shared vocabulary so the
        textual cloud stays dense and structure-free; names carry only the
        technique id (``technique t00001``), whose ``technique`` token is
        stopped out.
        """
        rng = random.Random(self._MASS_SEED)
        pool_words = " ".join(self._SHARED_VOCABULARY).split()
        if plan is None:
            plan = [(self._UNIFORM_TACTIC, 449)]
        gaps: list[GapItem] = []
        serial = 0
        for tactic, count in plan:
            for _ in range(count):
                serial += 1
                technique_id = f"T{serial:05d}"
                gaps.append(
                    GapItem(
                        technique_attack_id=technique_id,
                        name=f"technique {technique_id.lower()}",
                        tactic=tactic,
                        description=" ".join(rng.sample(pool_words, k=rng.randint(8, 12))),
                    )
                )
        assert len(gaps) == 449
        return gaps

    def test_uniform_signature_mass_collapses_to_single_cluster(self) -> None:
        """449 gaps without exploitable tactic structure -> ONE cluster."""
        gaps = self._mass_gaps()
        clusters = cluster_gaps(gaps, make_params())
        assert len(clusters) == 1, (
            "expected the conservative single-cluster fallback measured on the "
            "real gap set (best silhouette ~0.168 < 0.20); a multi-cluster "
            "result means the synthetic mass gained separable structure -- "
            "review the generator before loosening this assertion"
        )
        only = clusters[0]
        assert only.size == 449
        assert set(only.technique_ids) == {g.technique_attack_id for g in gaps}
        assert only.summary.startswith("449 undetected techniques")
        assert only.label

    def test_multi_tactic_structure_legitimately_separates(self) -> None:
        """The same scale WITH tagged tactic structure must NOT collapse.

        Guards against the policy degrading into always-single-cluster: an
        overwhelmingly lopsided but genuinely tagged mass separates into
        multiple clusters (each accepted cluster still holds >= 2 members)
        under the identical seed and params.
        """
        gaps = self._mass_gaps(plan=self._MULTI_TACTIC_COUNTS)
        clusters = cluster_gaps(gaps, make_params())
        assert len(clusters) >= 2
        covered: set[str] = set()
        for cluster in clusters:
            covered.update(cluster.technique_ids)
            assert cluster.size >= 2
        assert len(covered) == 449


# ---------------------------------------------------------------------------
# Feature-matrix semantics (via the module's _build_feature_matrix helper)
# ---------------------------------------------------------------------------

@requires_feature_builder
class TestFeatureMatrixSemantics:
    """Unit checks on the one-hot + TF-IDF feature construction.

    Assertions hold regardless of backend details because comparisons use
    self-normalised rows and scale-invariant ratios only.
    """

    def builder(self) -> Callable[..., Any]:
        """Return the feature builder (guaranteed present by the skip marker)."""
        builder = _find_feature_builder()
        assert builder is not None
        return builder

    def _matrix(self, items: Sequence[GapItem], max_vocab: int = 200) -> np.ndarray:
        return _as_matrix(self.builder()(list(items), max_vocab))

    def test_shape_finite_nonnegative(self) -> None:
        """Output is (n, >=14), finite and non-negative everywhere."""
        items = themed_gaps(items_per_theme=4)
        matrix = self._matrix(items)
        assert matrix.shape[0] == len(items)
        assert matrix.shape[1] >= len(CANONICAL_TACTICS)
        assert bool(np.isfinite(matrix).all())
        assert bool((matrix >= 0.0).all())

    def test_onehot_block_positions_follow_canonical_order(self) -> None:
        """Row argmax inside the first 14 columns sits at the tactic's index."""
        items = [
            make_gap(
                f"T{i:03d}",
                tactic,
                f"topictoken{i:03d} zetaquad sentinelphrase",
                name="",
            )
            for i, tactic in enumerate(CANONICAL_TACTICS)
        ]
        matrix = self._matrix(items)
        head = matrix[:, : len(CANONICAL_TACTICS)]
        for i, tactic in enumerate(CANONICAL_TACTICS):
            active = np.flatnonzero(head[i] > 1e-9)
            assert list(active) == [i], (
                f"tactic {tactic!r}: expected sole one-hot hit at column {i}, "
                f"got {active.tolist()}"
            )

    def test_unknown_tactic_leaves_onehot_block_zero(self) -> None:
        """Non-canonical tactics degrade to a zero block instead of raising."""
        items = [
            make_gap("T001", "not-a-real-tactic", "zetaquad sentinelphrase", name=""),
            make_gap("T002", "", "zetaquad sentinelphrase", name=""),
        ]
        matrix = self._matrix(items)
        head = matrix[:, : len(CANONICAL_TACTICS)]
        assert float(np.max(np.abs(head))) < 1e-12
        assert float(np.max(matrix[:, len(CANONICAL_TACTICS):])) > 1e-9

    def test_case_insensitive_tokenisation(self) -> None:
        """Casing never changes the resulting feature row."""
        items = [
            make_gap("T001", "execution", "Kerberos Ticket Renewal", name=""),
            make_gap("T002", "execution", "kerberos ticket renewal", name=""),
            make_gap("T003", "execution", "unrelated filler vocabulary item", name=""),
            make_gap("T004", "execution", "another distinct filler entry", name=""),
        ]
        matrix = self._matrix(items)
        u = _self_normalized(matrix[0])
        v = _self_normalized(matrix[1])
        assert float(np.max(np.abs(u - v))) < 1e-9

    def test_tokens_shorter_than_three_characters_ignored(self) -> None:
        """The [a-z0-9]{3,} rule drops 1-2 character tokens entirely."""
        items = [
            make_gap("T001", "execution", "ab zetaquad", name=""),
            make_gap("T002", "execution", "zetaquad", name=""),
            make_gap("T003", "execution", "unrelated filler vocabulary item", name=""),
            make_gap("T004", "execution", "another distinct filler entry", name=""),
        ]
        matrix = self._matrix(items)
        u = _self_normalized(matrix[0])
        v = _self_normalized(matrix[1])
        assert float(np.max(np.abs(u - v))) < 1e-9

    @pytest.mark.parametrize("stopword", CONTRACT_STOPWORDS)
    def test_contract_stopwords_have_zero_weight(self, stopword: str) -> None:
        """A stopped-out token never reaches the vocabulary nor the row.

        The corpus holds seven documents of ``<stopword> zetaquad`` plus a
        control document of bare ``zetaquad``: if the stopword were weighted,
        the vocabulary would contain more than the control term and the
        stopword rows would differ from the control row.
        """
        items = [
            make_gap(f"T{i:03d}", "collection", f"{stopword} zetaquad", name="")
            for i in range(1, len(CONTRACT_STOPWORDS) + 1)
        ]
        items.append(make_gap("T099", "collection", "zetaquad", name=""))
        raw = self.builder()(list(items), 200)
        matrix = np.asarray(raw[0] if isinstance(raw, tuple) else raw, dtype=float)
        vocab = tuple(raw[1]) if isinstance(raw, tuple) and len(raw) > 1 else ()
        assert vocab == ("zetaquad",), (
            f"stopword {stopword!r} leaked into the vocabulary: {vocab}"
        )
        tail = matrix[:, len(CANONICAL_TACTICS):]
        for position, row in enumerate(tail[:-1]):
            assert bool(np.allclose(row, tail[-1])), (
                f"stopword row {position} differs from the control row"
            )
        assert float(np.max(tail[-1])) > 1e-9, "control token unexpectedly dropped"

    def test_vocabulary_capped_at_max_vocab(self) -> None:
        """Total columns never exceed 14 canonical + configured max_vocab."""
        items = [
            make_gap(f"T{i:04d}", "collection", f"uniqtok{i:04d} zetaquad", name="")
            for i in range(230)
        ]
        matrix = self._matrix(items)
        assert matrix.shape[1] <= len(CANONICAL_TACTICS) + 200
        assert matrix.shape[1] > len(CANONICAL_TACTICS)

    def test_max_vocab_override_respected(self) -> None:
        """A smaller configured cap shrinks the TF-IDF block accordingly."""
        items = [
            make_gap(f"T{i:04d}", "collection", f"uniqtok{i:04d} zetaquad", name="")
            for i in range(60)
        ]
        matrix = self._matrix(items, max_vocab=10)
        assert matrix.shape[1] <= len(CANONICAL_TACTICS) + 10

    def test_empty_description_yields_tfidf_silent_row(self) -> None:
        """An empty-tokenized technique keeps its one-hot and a zero tail."""
        items = [
            make_gap("T001", "execution", "", name=""),
            make_gap("T002", "persistence", "registry autorun keys planted", name=""),
            make_gap("T003", "execution", "script interpreter payload spawned", name=""),
        ]
        matrix = self._matrix(items)
        tail = matrix[:, len(CANONICAL_TACTICS):]
        assert float(np.max(tail[0])) < 1e-9
        head_argmax = int(np.argmax(matrix[0, : len(CANONICAL_TACTICS)]))
        assert CANONICAL_TACTICS[head_argmax] == "execution"

    def test_repeated_token_growth_is_sublinear(self) -> None:
        """Weight growth for a x4-repeated token matches 1+ln(tf), not tf.

        Two documents share three filler tokens; one repeats ``malware`` four
        times. Every compared column sees the same per-row scale constant
        (row normalisation folds into it), estimated from the filler-column
        weight ratios; the repeated-token ratio divided by that constant must
        land at sublinear ``1 + ln(4) ~= 2.386`` -- linear tf would predict
        4.0 and binary tf 1.0.
        """
        base = "quadzed etavon thetak"
        items = [
            make_gap("T001", "collection", f"malware {base}", name=""),
            make_gap("T002", "collection", "malware malware malware malware " + base, name=""),
        ]
        matrix = self._matrix(items)
        u = _self_normalized(matrix[0])
        v = _self_normalized(matrix[1])

        common = (u > 1e-12) & (v > 1e-12)
        assert int(common.sum()) >= 4, "expected shared filler columns"
        safe_u = np.where(u > 0, u, 1.0)
        ratios = np.where(common, v / safe_u, 0.0)

        median_ratio = float(np.median(ratios[common]))
        outlier_idx = int(np.argmax(np.abs(ratios - median_ratio)))
        others = [j for j in np.flatnonzero(common) if j != outlier_idx]
        rho = float(np.median(v[others] / u[others]))  # per-row scale constant
        repeated_ratio = float((v[outlier_idx] / u[outlier_idx]) / rho)

        assert outlier_idx >= len(CANONICAL_TACTICS), "outlier must sit in tfidf block"
        assert 2.0 < repeated_ratio < 3.0, (
            f"repeated-token growth ratio {repeated_ratio:.3f} outside the "
            "sublinear band (1+ln 4 ~= 2.386)"
        )

    def test_feature_matrix_deterministic_across_calls(self) -> None:
        """Same inputs rebuild the exact same matrix."""
        items = themed_gaps(items_per_theme=4)
        first = self._matrix(items)
        second = self._matrix(items)
        assert first.shape == second.shape
        assert bool(np.array_equal(first, second))
