"""Label-surface tests for the gap-clustering layer (Phase 3, Wave 2, item F).

Scope of THIS module -- the ``GapCluster`` *label* and *summary* contract plus
the clustering policy edges that shape them:

* ``cluster_gaps`` returns a ``tuple[GapCluster, ...]`` (contract F overrides
  the older list-return sketch in ``research/swarm2-planning-designs.md``).
* ``GapCluster.label`` is ``"{majority tactic}: {top-2 distinguishing
  keywords}"``, where a distinguishing keyword scores
  ``mean(tfidf-in-cluster) - mean(tfidf-outside) > 0.05``.
* ``GapCluster.summary`` is one sentence starting ``"<n> undetected
  techniques"``, containing the two keywords joined by ``"/"`` and mentioning
  the majority tactic.
* Policy edges: empty input -> ``()``, ``n <= 3`` -> single cluster without
  KMeans, identical feature vectors (NaN silhouette) -> conservative
  single-cluster fallback, accepted clusters never smaller than 2 members.
* Hashability/frozenness per Wave-1 finding (A): frozen dataclasses whose
  collection fields are tuples only, natively hashable (no pickle escape
  hatch through ``st.cache_data``).
* Seed determinism: identical inputs -> byte-identical output (sklearn
  KMeans with pinned ``random_state=42`` was verified cross-process,
  ``research/p3-wave1-full-results.md`` agent-187).

Empirical anchors encoded here (same research file):

* The real ~449-gap Windows corpus tops out at mean silhouette 0.168 across
  k=2..6 (< 0.20), so the conservative ONE-cluster outcome is CORRECT
  behaviour; agent-185's Monte-Carlo shows 0.20 is the false-split/power
  knee. We emulate that degenerate regime with identical-vector corpora
  instead of touching the DB (DB-backed scenarios belong to the coverage
  engine's own tests).
* ``0.20`` silhouette threshold and ``k_max=6`` / ``min_clusterable=4`` come
  from config contract H; defaults are asserted via behaviour, not by
  importing private helpers.

This file deliberately does NOT duplicate ``tests/test_gap_clustering.py``
(general clustering behaviour, owned by its sibling); assertions here pin
only contract-stated label/summary/policy surface and stay black-box.

The implementing sibling owns ``src/analysis/gap_clustering.py``; field
names follow the Wave-2 contract F exactly:
``GapItem(technique_attack_id, name, tactic, description)``.
"""

from __future__ import annotations

import copy
import dataclasses
import inspect
import itertools
import logging
import re
from typing import Any, Mapping, Sequence

import pytest

from analysis.gap_clustering import GapCluster, GapItem, cluster_gaps
from config_loader import DEFAULT_CONFIG

logger = logging.getLogger(__name__)

#: Pure-function tests: no filesystem, no DB, no network (pyproject markers).
pytestmark = pytest.mark.unit

#: The 14 Enterprise tactics in canonical ATT&CK order (contract D). Used to
#: pick valid tactic names for synthetic items; ordering itself is a coverage
#: engine concern, not a clustering concern.
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

#: Mandatory stopword floor from contract F (tokenizer must drop these).
STOPWORD_FLOOR: frozenset[str] = frozenset(
    {"technique", "adversaries", "may", "using", "windows", "attack", "system"}
)

#: Tokenizer shape from contract F: lowercase ``[a-z0-9]{3,}``.
TOKEN_RE = re.compile(r"[a-z0-9]{3,}\Z")

# ---------------------------------------------------------------------------
# Controlled-vocabulary corpora
# ---------------------------------------------------------------------------
# Every content token in the sentences below is enumerated in the matching
# tuple, so any top-2 distinguishing keyword MUST come from the theme's own
# vocabulary (theme tokens appear only in their theme's documents; the shared
# tokens appear everywhere and score ~0 difference, below the 0.05 bar).
# This makes keyword-membership assertions implementation-independent.

EXEC_TACTIC = "execution"
PHISH_TACTIC = "initial-access"
CRED_TACTIC = "credential-access"

EXEC_TOKENS: tuple[str, ...] = ("powershell", "script", "encoded", "commands")
PHISH_TOKENS: tuple[str, ...] = ("phishing", "email", "spear", "attachments")
SHARED_TOKENS: tuple[str, ...] = ("abuse", "telemetry")  # both themes -> diff ~0

EXEC_SENTENCE = "adversaries may abuse powershell script encoded commands telemetry"
PHISH_SENTENCE = "adversaries may abuse phishing email spear attachments telemetry"

#: Clustering defaults from contract H (load_config fills these when absent;
#: until the config sibling lands, DEFAULT_CONFIG may not carry the key yet,
#: so these literals are the guaranteed floor).
_CONTRACT_CLUSTERING_DEFAULTS: dict[str, Any] = {
    "min_clusterable": 4,
    "k_max": 6,
    "silhouette_threshold": 0.2,
    "max_vocab": 200,
    "seed": 42,
}

_id_counter = itertools.count(1)


def make_gap(
    tactic: str,
    text: str,
    *,
    name: str | None = None,
    attack_id: str | None = None,
) -> GapItem:
    """Build one synthetic :class:`GapItem` per contract-F field names.

    ``attack_id`` defaults to a unique synthetic id (``T1000.001``, ...) so
    repeated calls never collide; ``name`` defaults to the sentence itself
    (title-cased), keeping the name-token multiset inside the controlled
    vocabulary declared by the caller.
    """
    return GapItem(
        technique_attack_id=attack_id or f"T1000.{next(_id_counter):03d}",
        name=name if name is not None else text.title(),
        tactic=tactic,
        description=text,
    )


def execution_theme(count: int) -> list[GapItem]:
    """``count`` identical-text execution-themed gaps (one tight blob)."""
    return [make_gap(EXEC_TACTIC, EXEC_SENTENCE) for _ in range(count)]


def phishing_theme(count: int) -> list[GapItem]:
    """``count`` identical-text initial-access-themed gaps (second blob)."""
    return [make_gap(PHISH_TACTIC, PHISH_SENTENCE) for _ in range(count)]


def varied_credential_theme(count: int) -> list[GapItem]:
    """Credential-access gaps sharing one token set but varying word order.

    Same vocabulary everywhere means near-proportional tf-idf rows: clusters
    are barely separable, which stresses the min-size/silhouette guards
    without ever producing an invalid answer (policy invariant asserted).
    """
    base = ("credential", "lsass", "memory", "dumping")
    items: list[GapItem] = []
    rotations = itertools.cycle(
        [base[i:] + base[:i] for i in range(len(base))]
    )
    for rotation in rotations:
        if len(items) >= count:
            break
        text = "adversaries may abuse " + " ".join(rotation) + " telemetry"
        items.append(make_gap(CRED_TACTIC, text))
    return items


# ---------------------------------------------------------------------------
# Config-seam tolerant invocation
# ---------------------------------------------------------------------------


def _default_clustering_cfg() -> dict[str, Any]:
    """Clustering settings: shipped config overlaid on contract-H defaults."""
    merged = dict(_CONTRACT_CLUSTERING_DEFAULTS)
    loaded = copy.deepcopy(DEFAULT_CONFIG).get("clustering")
    if isinstance(loaded, Mapping):
        merged.update(loaded)
    return merged


_POSITIONAL_PARAMS = [
    param
    for param in inspect.signature(cluster_gaps).parameters.values()
    if param.kind
    in (
        inspect.Parameter.POSITIONAL_ONLY,
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
    )
]


_CFG_PARAM = _POSITIONAL_PARAMS[1] if len(_POSITIONAL_PARAMS) > 1 else None
#: True only when callers MUST supply the settings argument themselves.
_CFG_REQUIRED = (
    _CFG_PARAM is not None and _CFG_PARAM.default is inspect.Parameter.empty
)


def run_cluster_gaps(items: Sequence[GapItem]) -> tuple[GapCluster, ...]:
    """Invoke ``cluster_gaps`` tolerating every supported settings convention.

    Contract F fixes behaviour but leaves the optional-settings seam to the
    implementing sibling. Three shapes exist:

    * no second positional parameter, or a defaulted one (the shipped
      ``ClusteringParams | None = None``, which carries the contract-H
      defaults internally) -- called bare so the implementation's own
      defaults apply;
    * a required full-config mapping accessed as ``cfg["clustering"]``;
    * a required clustering sub-mapping accessed as ``cfg["seed"]`` --
      retried once on ``KeyError`` only; any other exception propagates.
    """
    frozen_items = tuple(items)
    if not _CFG_REQUIRED:
        return cluster_gaps(frozen_items)
    clustering = _default_clustering_cfg()
    try:
        return cluster_gaps(frozen_items, {"clustering": clustering})
    except KeyError:
        logger.debug(
            "cluster_gaps rejected full-config convention; "
            "retrying with clustering sub-mapping"
        )
        return cluster_gaps(frozen_items, clustering)


# ---------------------------------------------------------------------------
# Assertion helpers
# ---------------------------------------------------------------------------


def assert_basic_cluster_shape(cluster: GapCluster, expected_size: int) -> None:
    """Contract-level invariants every returned cluster must satisfy."""
    assert isinstance(cluster, GapCluster)
    assert isinstance(cluster.cluster_id, int) and cluster.cluster_id >= 0
    assert isinstance(cluster.technique_ids, tuple), (
        "collection fields must be tuples (hashability contract A)"
    )
    assert len(cluster.technique_ids) == cluster.size == expected_size
    assert isinstance(cluster.label, str) and cluster.label.strip()
    assert isinstance(cluster.summary, str)
    assert cluster.summary.endswith("."), "summary is one sentence ending in '.'"


def extract_label_parts(label: str) -> tuple[str, tuple[str, str]]:
    """Split ``"{tactic}: {kw1}{sep}{kw2}"`` into normalized parts.

    Returns ``(tactic, keywords)`` where ``tactic`` is lowercased with spaces
    folded to hyphens (tolerates both ``"Execution"`` and ``"execution"``),
    and keywords are exactly two lowercase tokens split on any non-word run
    (tolerates space, comma or middot separators between them).
    """
    assert ":" in label, f"label must be '{{majority tactic}}: {{keywords}}', got {label!r}"
    prefix, _, rest = label.partition(":")
    tactic = prefix.strip().lower().replace(" ", "-")
    keywords = tuple(tok for tok in re.split(r"[^a-z0-9]+", rest.lower()) if tok)
    return tactic, keywords  # type: ignore[return-value]


def assert_themed_cluster(
    cluster: GapCluster,
    tactic: str,
    vocab: tuple[str, ...],
) -> tuple[str, str]:
    """Assert one accepted cluster is labeled from its own theme vocab.

    Checks the majority-tactic prefix, exactly two distinct in-vocabulary
    keyword tokens (valid tokenizer shapes, not stopwords), and a summary
    that opens with "<n> undetected techniques", slash-joins the same two
    keywords (either order) and mentions the tactic. Returns the keyword pair.
    """
    assert_basic_cluster_shape(cluster, expected_size=len(cluster.technique_ids))

    label_tactic, keywords = extract_label_parts(cluster.label)
    assert label_tactic == tactic, (
        f"majority tactic mismatch: {label_tactic!r} != {tactic!r} "
        f"in label {cluster.label!r}"
    )
    assert len(keywords) == 2, f"label must carry exactly 2 keywords: {cluster.label!r}"
    kw1, kw2 = keywords
    assert kw1 != kw2, f"duplicated keyword pair in {cluster.label!r}"
    allowed = set(vocab) | set(SHARED_TOKENS)
    for kw in keywords:
        assert TOKEN_RE.fullmatch(kw), f"keyword {kw!r} violates tokenizer shape"
        assert kw not in STOPWORD_FLOOR, f"keyword {kw!r} is a stopword"
        assert kw in allowed, (
            f"keyword {kw!r} outside controlled vocab {sorted(allowed)} "
            f"(label {cluster.label!r})"
        )

    summary = cluster.summary.lower()
    assert re.match(r"\d+ undetected techniques", summary), (
        f"summary must open '<n> undetected techniques': {cluster.summary!r}"
    )
    slash_pair = (
        re.search(rf"{kw1}\s*/\s*{kw2}", summary)
        or re.search(rf"{kw2}\s*/\s*{kw1}", summary)
    )
    assert slash_pair, (
        f"summary must contain '{kw1}/{kw2}' joined by '/': {cluster.summary!r}"
    )
    folded = summary.replace(" ", "-")
    assert tactic in folded, f"summary must mention tactic {tactic!r}: {cluster.summary!r}"
    return kw1, kw2


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestPolicyEdges:
    """Clustering policy edge cases that bound the labeling surface."""

    def test_empty_input_returns_empty_tuple(self) -> None:
        """n == 0 -> ``()``: graceful skip, tuple type per contract F."""
        result = run_cluster_gaps([])
        assert result == ()
        assert isinstance(result, tuple)

    @pytest.mark.parametrize("n", [1, 2, 3])
    def test_tiny_inputs_collapse_to_single_cluster(self, n: int) -> None:
        """n <= 3 -> exactly one cluster holding every id (no KMeans path).

        Whether KMeans actually ran is unobservable black-box; the contract
        fixes the observable outcome: one cluster, all ids preserved.
        """
        items = (execution_theme(n // 2 + 1) + phishing_theme(n - n // 2 - 1))[:n]
        assert len(items) == n

        result = run_cluster_gaps(items)

        assert isinstance(result, tuple) and len(result) == 1
        cluster = result[0]
        assert_basic_cluster_shape(cluster, n)
        assert set(cluster.technique_ids) == {item.technique_attack_id for item in items}

    def test_identical_vectors_fall_back_to_single_cluster(self) -> None:
        """NaN silhouette (identical feature vectors) -> conservative fallback.

        Mirrors the measured real-world regime: the ~449-gap corpus peaks at
        mean silhouette 0.168 < 0.20 across k=2..6, so ONE cluster is the
        correct outcome (agent-185). Identical texts give literally zero
        pairwise distance -> silhouette NaN -> forced fallback.
        """
        items = [
            make_gap(CRED_TACTIC, EXEC_SENTENCE, attack_id=f"T1000.{i:03d}")
            for i in range(1, 13)
        ]

        result = run_cluster_gaps(items)

        assert isinstance(result, tuple) and len(result) == 1
        cluster = result[0]
        assert_basic_cluster_shape(cluster, 12)
        assert set(cluster.technique_ids) == {item.technique_attack_id for item in items}
        # Degenerate geometry leaves no meaningful "outside" to distinguish
        # against: only require non-empty strings, not themed structure.
        logger.debug("fallback label=%r summary=%r", cluster.label, cluster.summary)

    def test_min_size_invariant_on_varied_corpus(self) -> None:
        """Every accepted multi-cluster partition has all sizes >= 2.

        Near-proportional vectors make acceptance borderline; whichever way
        the guards decide, the policy invariant must hold and ids must be
        partitioned losslessly.
        """
        items = varied_credential_theme(12)
        ids = [item.technique_attack_id for item in items]

        result = run_cluster_gaps(items)

        assert isinstance(result, tuple) and result
        if len(result) > 1:
            sizes = sorted(c.size for c in result)
            assert sizes[0] >= 2, f"accepted cluster below min size: sizes={sizes}"
        flattened = [tid for c in result for tid in c.technique_ids]
        assert sorted(flattened) == sorted(ids)
        assert len(set(flattened)) == len(flattened), "clusters overlap"


class TestLabeledClusters:
    """Label/summary formatting on a corpus where clustering must accept."""

    def test_two_separable_themes_yield_themed_labels(self) -> None:
        """4+4 disjoint-vocab blobs -> 2 accepted clusters, themed labels."""
        items = execution_theme(4) + phishing_theme(4)

        result = run_cluster_gaps(items)

        assert isinstance(result, tuple)
        assert len(result) == 2, (
            f"well-separated themes must accept k=2, got {len(result)} cluster(s)"
        )

        seen_pairs: list[tuple[str, str]] = []
        seen_ids: list[str] = []
        for cluster in result:
            member_tactics = {
                item.tactic
                for item in items
                if item.technique_attack_id in set(cluster.technique_ids)
            }
            assert len(member_tactics) == 1, "blobs must not be mixed"
            tactic = next(iter(member_tactics))
            vocab = EXEC_TOKENS if tactic == EXEC_TACTIC else PHISH_TOKENS
            seen_pairs.append(assert_themed_cluster(cluster, tactic, vocab))
            seen_ids.extend(cluster.technique_ids)

        # Distinct themes must not share a keyword pair.
        assert seen_pairs[0] != seen_pairs[1]

        # Lossless, disjoint partition of the input ids.
        all_ids = [item.technique_attack_id for item in items]
        assert sorted(seen_ids) == sorted(all_ids)
        assert len(set(seen_ids)) == len(seen_ids)

        # Cluster ids are unique non-negative ints (ordering unpinned).
        cluster_ids = [c.cluster_id for c in result]
        assert len(set(cluster_ids)) == len(cluster_ids)

    def test_n_equals_4_respects_k_upper_bound(self) -> None:
        """At n=4 the sweep is k in 2..min(k_max, n//2)=2: only a 2+2 split.

        A conforming k-selection can therefore never emit three clusters for
        four well-separated items; the accepted partition must be exactly
        two size-2 blobs.
        """
        items = execution_theme(2) + phishing_theme(2)

        result = run_cluster_gaps(items)

        assert len(result) == 2, (
            f"expected the single admissible k=2 split, got sizes="
            f"{[c.size for c in result]}"
        )
        assert sorted(c.size for c in result) == [2, 2]
        for cluster in result:
            member_tactics = {
                item.tactic
                for item in items
                if item.technique_attack_id in set(cluster.technique_ids)
            }
            assert len(member_tactics) == 1
            tactic = next(iter(member_tactics))
            vocab = EXEC_TOKENS if tactic == EXEC_TACTIC else PHISH_TOKENS
            assert_themed_cluster(cluster, tactic, vocab)


class TestDeterminismAndTypes:
    """Seed determinism and the frozen/hashable return-type contract."""

    def test_repeated_calls_are_byte_identical(self) -> None:
        """Identical inputs -> identical output objects (seeded pipeline).

        In-process double-call pins seed determinism of the whole feature ->
        KMeans -> label pipeline; cross-process determinism was verified for
        sklearn KMeans(random_state=42) during Wave 1 (agent-187) and cannot
        be re-checked here without subprocesses, which this suite forbids.
        """
        items = execution_theme(3) + phishing_theme(3)

        first = run_cluster_gaps(items)
        second = run_cluster_gaps(items)

        assert first == second, "equal inputs must produce equal outputs"
        assert repr(first) == repr(second), "output must be byte-identical"
        for c1, c2 in zip(first, second):
            assert hash(c1) == hash(c2)

    def test_return_type_is_tuple_of_frozen_hashable_clusters(self) -> None:
        """tuple[GapCluster, ...]; frozen dataclasses; tuple collections (A)."""
        items = execution_theme(2) + phishing_theme(2)

        result = run_cluster_gaps(items)

        assert isinstance(result, tuple)
        for cluster in result:
            assert dataclasses.is_dataclass(cluster)
            with pytest.raises(dataclasses.FrozenInstanceError):
                cluster.label = "mutated"  # type: ignore[misc]
            hash(cluster)  # must not raise TypeError
            assert isinstance(cluster.technique_ids, tuple)
            assert all(isinstance(tid, str) for tid in cluster.technique_ids)

        item = items[0]
        assert dataclasses.is_dataclass(item)
        with pytest.raises(dataclasses.FrozenInstanceError):
            item.tactic = "other"  # type: ignore[misc]
        hash(item)  # st.cache_data-safe even without pickling

    def test_accepts_tuple_and_list_sequences(self) -> None:
        """Any Sequence input works; output type stays tuple either way."""
        list_input = execution_theme(2) + phishing_theme(2)
        tuple_input = tuple(list_input)

        from_list = run_cluster_gaps(list_input)
        from_tuple = run_cluster_gaps(tuple_input)

        assert isinstance(from_list, tuple)
        assert from_list == from_tuple
