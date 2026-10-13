"""Gap clustering for undetected ATT&CK techniques (Phase 3, Wave 2).

Turns a set of uncovered techniques (:class:`GapItem`) into human-readable
clusters (:class:`GapCluster`) so the dashboard can explain detection gaps
*in aggregate* instead of presenting a flat list of technique IDs.

Pipeline (Phase-3 contract F)
-----------------------------
1. **Feature building** -- one float64 row per item, concatenated from two
   blocks without re-normalisation (so each block keeps its intended scale):

   * a 14-dimensional tactic one-hot block scaled by ``w = 2.0`` following
     :data:`CANONICAL_TACTICS`; a tactic outside the canonical list (or an
     empty one) contributes an all-zero block rather than raising, because
     clustering must stay resilient to upstream tagging noise;
   * a TF-IDF block over the ``"{name} {description}"`` document: lowercased,
     tokens matching ``[a-z0-9]{3,}``, the curated English + ATT&CK
     boilerplate stop-word set :data:`_STOPWORDS` (superset of the mandated
     ``{technique, adversaries, may, using, windows, attack, system}``),
     sublinear term frequency, smooth IDF, L2 normalisation, and a vocabulary
     cap of ``max_vocab`` terms ranked by corpus frequency with alphabetic
     tie-breaking (scikit-learn ``max_features`` semantics).

2. **Model sweep** -- for ``n >= min_clusterable`` items, k-means
   (euclidean, ``random_state=params.seed``, ``n_init=10``) is fitted for
   every ``k`` in ``range(2, min(k_max, n // 2) + 1)`` and scored by the mean
   silhouette coefficient. The best score wins; because the sweep runs in
   ascending ``k`` and replacement requires a *strictly* greater score, ties
   deterministically favour the smaller ``k``.

3. **Acceptance gate** -- the swept solution is accepted only when its mean
   silhouette is ``>= params.silhouette_threshold`` AND every resulting
   cluster holds at least two items. Otherwise -- including when the
   silhouette is NaN (e.g. duplicated feature vectors) or a candidate fails
   outright -- the function falls back to a single cluster containing every
   item. For ``n < min_clusterable`` no model is fitted at all. This
   conservative fallback is deliberate: on the current production gap set
   (~449 techniques spanning all tactics) the measured mean silhouette is
   approximately 0.168, below the 0.20 gate, and reporting ONE cluster is
   the correct honest outcome rather than inventing structure.

4. **Labelling** -- each cluster is labelled ``"{majority tactic}: {kw1}/{kw2}"``.
   A keyword's distinguishing score is its mean TF-IDF weight inside the
   cluster minus its mean weight outside it; terms scoring above 0.05
   qualify. If fewer than two terms qualify, the remaining label slots are
   padded with the highest mean-within-cluster terms and finally with the
   literal placeholder ``general`` so labels stay well-formed. The
   single-cluster fallback has no "outside", so its keywords are simply the
   top mean-within-cluster terms. Summaries read
   ``"{size} undetected techniques cluster around {kw1}/{kw2} in the {tactic} tactic."``

Determinism
-----------
scikit-learn was chosen over a hand-rolled TF-IDF/KMeans deliberately: it is
an existing pinned project dependency (``requirements.txt``, spec section
5.2), its defaults encode exactly the semantics used by the Wave-1
measurements, and with a fixed ``random_state`` it reproduces identical
results across processes on a given installation. Output ordering never
depends on k-means' internal label permutation: clusters are re-sorted
canonically (majority tactic in :data:`CANONICAL_TACTICS` order, then the
smallest technique ID) before ``cluster_id`` values are assigned.

Hashability
-----------
All public dataclasses are frozen and contain only primitives and tuples, so
every returned value is natively hashable and picklable (Wave-1 contract A).

Config bridge
-------------
:class:`ClusteringParams` mirrors the optional top-level ``clustering`` config
section (``min_clusterable``, ``k_max``, ``silhouette_threshold``,
``max_vocab``, ``seed``); :meth:`ClusteringParams.from_config` applies the
same defaults and validation rules (``ValueError`` on bad type or range) that
the central config loader uses for that section.
"""

from __future__ import annotations

import logging
import math
import warnings
from collections import Counter
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

import numpy as np
from sklearn.cluster import KMeans
from sklearn.exceptions import ConvergenceWarning
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import silhouette_score

logger = logging.getLogger(__name__)

__all__ = [
    "CANONICAL_TACTICS",
    "ClusteringParams",
    "GapCluster",
    "GapItem",
    "cluster_gaps",
]

#: Canonical MITRE ATT&CK Enterprise tactic order used for the one-hot block,
#: majority-tactic tie-breaking and canonical output ordering. Kept local (and
#: intentionally duplicated from the coverage engine) so this module has no
#: compile-time coupling to sibling deliverables.
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

_TACTIC_INDEX: dict[str, int] = {name: pos for pos, name in enumerate(CANONICAL_TACTICS)}

#: Relative weight of the tactic one-hot block versus the unit-norm TF-IDF block.
_TACTIC_BLOCK_WEIGHT: float = 2.0

#: Number of leading feature-matrix columns occupied by the one-hot block.
_N_TACTIC_DIMS: int = len(CANONICAL_TACTICS)

#: Tokenizer shared with the vectorizer: lowercase alphanumerics, min 3 chars.
_TOKEN_PATTERN = r"(?u)\b[a-z0-9]{3,}\b"

#: Minimum (mean-inside minus mean-outside) score for a distinguishing keyword.
_KEYWORD_MARGIN: float = 0.05

#: Placeholder when a cluster has no usable lexical signal at all.
_PLACEHOLDER_KEYWORD = "general"

#: Label for clusters whose items carry no tactic tag at all.
_UNTAGGED_TACTIC = "uncategorized"

#: English function words plus ATT&CK-description boilerplate. Superset of the
#: contract-mandated {technique, adversaries, may, using, windows, attack,
#: system}; all entries are plain lowercase tokens so they stay consistent
#: with the ``[a-z0-9]{3,}`` analyzer (no scikit-learn stop-word warnings).
#: Words carrying real signal (e.g. "credential", "registry", "user") are
#: deliberately NOT stopped.
_STOPWORDS: frozenset[str] = frozenset({
    # mandated domain boilerplate
    "technique", "techniques", "adversary", "adversaries", "may", "using",
    "windows", "attack", "system", "systems",
    # english function words / auxiliaries (sub-3-char entries are inert under
    # the [a-z0-9]{3,} tokenizer but kept for completeness)
    "a", "all", "also", "am", "an", "and", "are", "as", "at", "be", "being",
    "but", "by", "can", "do", "doing", "down", "for", "from", "he", "how",
    "i", "if", "in", "is", "it", "its", "just", "my", "no", "now", "of",
    "on", "or", "so", "to", "up", "we", "you",
    "about", "above", "across", "after", "against", "along", "although",
    "always", "among", "another", "any", "anybody", "anyone", "anything",
    "around", "became", "because", "become", "becomes", "been", "before",
    "behind", "below", "beside", "besides", "between", "beyond", "both",
    "came", "cannot", "come", "could", "did", "does", "done", "during",
    "each", "either", "else", "enough", "even", "ever", "every", "everybody",
    "everyone", "everything", "except", "few", "first", "found", "further",
    "gave", "get", "give", "given", "goes", "gone", "got", "had", "has",
    "have", "having", "hence", "her", "here", "hereby", "herein", "hereof",
    "hereon", "hereupon", "hers", "herself", "him", "himself", "his",
    "however", "indeed", "instead", "into", "itself", "let", "like", "little",
    "made", "make", "many", "me", "meanwhile", "might", "mine", "more",
    "moreover", "most", "mostly", "much", "must", "myself", "near", "neither",
    "never", "nevertheless", "next", "nobody", "none", "nonetheless", "nor",
    "not", "nothing", "nowhere", "off", "often", "once", "one", "onto",
    "only", "other", "others", "otherwise", "ought", "our", "ours",
    "ourselves", "out", "over", "own", "per", "perhaps", "please", "put",
    "quite", "rather", "really", "regarding", "said", "same", "say", "says",
    "second", "seem", "seemed", "seeming", "seems", "several", "shall",
    "she", "should", "show", "shown", "side", "since", "some", "somebody",
    "somehow", "someone", "something", "sometime", "sometimes", "somewhat",
    "somewhere", "soon", "still", "such", "take", "taken", "tell", "than",
    "that", "the", "their", "theirs", "them", "themselves", "then", "thence",
    "there", "thereby", "therefore", "therein", "thereof", "thereon",
    "thereto", "thereupon", "these", "they", "thing", "things", "third",
    "this", "those", "though", "three", "through", "throughout", "thru",
    "thus", "together", "too", "toward", "towards", "tried", "tries", "try",
    "two", "under", "underneath", "undo", "unless", "unlike", "until", "unto",
    "upon", "upward", "use", "used", "uses", "utterly", "various", "very",
    "via", "was", "way", "ways", "well", "went", "were", "what", "whatsoever",
    "when", "whence", "whenever", "where", "whereas", "whereby", "wherein",
    "whereof", "whereon", "wherever", "whether", "which", "while", "whither",
    "who", "whoever", "whole", "whom", "whose", "why", "will", "with",
    "within", "without", "would", "yet", "your", "yours", "yourself",
    "yourselves",
})


@dataclass(frozen=True)
class GapItem:
    """One undetected technique handed to the clustering stage.

    Attributes:
        technique_attack_id: ATT&CK technique identifier, e.g. ``T1059.001``.
        name: Human-readable technique name.
        tactic: Primary tactic tag (lowercase, ideally canonical).
        description: Technique description text used for TF-IDF features.
    """

    technique_attack_id: str
    name: str
    tactic: str
    description: str


@dataclass(frozen=True)
class GapCluster:
    """A labelled group of undetected techniques (contract F).

    Attributes:
        cluster_id: Stable ordinal, assigned after canonical ordering.
        label: ``"{majority tactic}: {kw1}/{kw2}"``.
        technique_ids: Member technique IDs, sorted ascending.
        summary: One-sentence human-readable cluster description.
        size: Number of member techniques (equals ``len(technique_ids)``).
    """

    cluster_id: int
    label: str
    technique_ids: tuple[str, ...]
    summary: str
    size: int


@dataclass(frozen=True)
class ClusteringParams:
    """Knobs mirroring the optional top-level ``clustering`` config section.

    Defaults match the documented config extension (contract H):
    ``{min_clusterable: 4, k_max: 6, silhouette_threshold: 0.2,
    max_vocab: 200, seed: 42}``.
    """

    min_clusterable: int = 4
    k_max: int = 6
    silhouette_threshold: float = 0.20
    max_vocab: int = 200
    seed: int = 42

    @classmethod
    def from_config(cls, section: Mapping[str, Any] | None) -> "ClusteringParams":
        """Build parameters from the ``clustering`` config mapping.

        Missing keys fall back to :class:`ClusteringParams` defaults. Unknown
        keys are logged and ignored (forward compatibility); known keys with
        a wrong type or out-of-range value raise ``ValueError``, mirroring
        the central config loader's behaviour for this section.

        Args:
            section: Raw ``clustering`` mapping (or ``None`` when absent).

        Returns:
            Validated parameters.

        Raises:
            ValueError: If a known key has a non-matching type or a value
                outside its permitted range.
        """
        raw = dict(section) if section else {}
        for key in sorted(set(raw) - {"min_clusterable", "k_max",
                                      "silhouette_threshold", "max_vocab",
                                      "seed"}):
            logger.warning("clustering config: ignoring unknown key %r", key)
        return cls(
            min_clusterable=_validated_int(raw, "min_clusterable", cls.min_clusterable, minimum=1),
            k_max=_validated_int(raw, "k_max", cls.k_max, minimum=2),
            silhouette_threshold=_validated_fraction(raw, "silhouette_threshold", cls.silhouette_threshold),
            max_vocab=_validated_int(raw, "max_vocab", cls.max_vocab, minimum=1),
            seed=_validated_seed(raw, "seed", cls.seed),
        )


def cluster_gaps(
    items: Iterable[GapItem],
    params: ClusteringParams | None = None,
) -> tuple[GapCluster, ...]:
    """Cluster undetected techniques into labelled gap clusters.

    Implements the full policy described in the module docstring: empty input
    yields ``()``; fewer than ``params.min_clusterable`` items yield one
    cluster without fitting any model; otherwise a seeded k-means sweep with
    silhouette selection runs, gated by ``params.silhouette_threshold`` and a
    minimum cluster size of two, falling back to a single cluster whenever
    the gate is not met (NaN silhouettes included).

    Args:
        items: Gap items to cluster. Duplicate ``technique_attack_id`` values
            are dropped with a warning (first occurrence wins).
        params: Clustering parameters; ``None`` uses the defaults.

    Returns:
        Tuple of frozen clusters, canonically ordered (majority tactic in
        :data:`CANONICAL_TACTICS` order, then smallest member technique ID).

    Raises:
        TypeError: If ``items`` contains non-:class:`GapItem` values or
            ``params`` is not a :class:`ClusteringParams`.
    """
    if params is None:
        params = ClusteringParams()
    elif not isinstance(params, ClusteringParams):
        raise TypeError(
            f"params must be ClusteringParams or None, got {type(params).__name__}"
        )

    materialised = list(items)
    for position, item in enumerate(materialised):
        if not isinstance(item, GapItem):
            raise TypeError(
                f"items[{position}] must be GapItem, got {type(item).__name__}"
            )
    materialised = _dedupe_by_technique_id(materialised)
    n_items = len(materialised)
    if n_items == 0:
        logger.info("cluster_gaps: no gap items supplied; returning ()")
        return ()

    matrix, vocab = _build_feature_matrix(materialised, params.max_vocab)

    if n_items < params.min_clusterable:
        logger.info(
            "cluster_gaps: %d item(s) <= min_clusterable=%d; single cluster, "
            "no KMeans fitted",
            n_items,
            params.min_clusterable,
        )
        return (_single_cluster(materialised, matrix, vocab),)

    best_score = -math.inf
    best_k: int | None = None
    best_labels: np.ndarray | None = None
    upper_k = min(params.k_max, n_items // 2)
    for k in range(2, upper_k + 1):
        model = KMeans(n_clusters=k, random_state=params.seed, n_init=10)
        # Degenerate geometry (e.g. duplicated feature vectors) makes
        # scikit-learn emit ConvergenceWarnings; route them through the module
        # logger instead of stderr so strict warning filters in CI stay happy.
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("ignore", ConvergenceWarning)
            labels = model.fit_predict(matrix)
        for caught_warning in caught:
            logger.warning(
                "cluster_gaps: KMeans(k=%d) emitted %s: %s",
                k,
                caught_warning.category.__name__,
                caught_warning.message,
            )
        try:
            score = float(silhouette_score(matrix, labels, metric="euclidean"))
        except ValueError as exc:
            # Defensive only: k <= n//2 < n and k >= 2 make degenerate label
            # counts practically impossible, but never let one bad candidate
            # abort the whole sweep.
            logger.warning("cluster_gaps: silhouette failed for k=%d (%s)", k, exc)
            continue
        if math.isnan(score):
            logger.warning(
                "cluster_gaps: NaN silhouette for k=%d (degenerate geometry); "
                "candidate rejected",
                k,
            )
            continue
        logger.debug("cluster_gaps: k=%d silhouette=%.4f", k, score)
        if score > best_score:
            best_score, best_k, best_labels = score, k, labels

    accepted = (
        best_labels is not None
        and best_score >= params.silhouette_threshold
        and int(np.bincount(best_labels, minlength=best_k or 0).min()) >= 2
    )
    if accepted:
        logger.info(
            "cluster_gaps: accepting k=%d (mean silhouette %.4f >= %.2f)",
            best_k,
            best_score,
            params.silhouette_threshold,
        )
        return _multi_clusters(materialised, matrix, vocab, best_labels)

    logger.info(
        "cluster_gaps: no candidate met the gate (best=%s, threshold=%.2f, "
        "n=%d); conservative single-cluster fallback",
        "none" if best_k is None else f"k={best_k} s={best_score:.4f}",
        params.silhouette_threshold,
        n_items,
    )
    return (_single_cluster(materialised, matrix, vocab),)


def _dedupe_by_technique_id(items: list[GapItem]) -> list[GapItem]:
    """Drop later duplicates of an already-seen ``technique_attack_id``."""
    seen: set[str] = set()
    unique: list[GapItem] = []
    duplicates: list[str] = []
    for item in items:
        if item.technique_attack_id in seen:
            duplicates.append(item.technique_attack_id)
        else:
            seen.add(item.technique_attack_id)
            unique.append(item)
    if duplicates:
        preview = ", ".join(sorted(set(duplicates))[:10])
        more = "" if len(set(duplicates)) <= 10 else " ..."
        logger.warning(
            "cluster_gaps: dropped %d duplicate gap item(s): %s%s",
            len(duplicates),
            preview,
            more,
        )
    return unique


def _build_feature_matrix(
    items: Sequence[GapItem],
    max_vocab: int,
) -> tuple[np.ndarray, tuple[str, ...]]:
    """Assemble the ``n x (14 + V)`` feature matrix.

    Columns ``0..13`` are the canonical tactic one-hot block scaled by
    :data:`_TACTIC_BLOCK_WEIGHT`; columns ``14..`` are the L2-normalised
    sublinear TF-IDF block over ``"{name} {description}"`` documents.

    Args:
        items: Deduplicated gap items, in stable input order.
        max_vocab: Maximum TF-IDF vocabulary size (corpus-frequency ranking,
            alphabetic tie-breaking).

    Returns:
        ``(matrix, vocab)`` where ``vocab`` is the selected vocabulary in
        column order (alphabetical, scikit-learn convention).
    """
    documents = [f"{item.name} {item.description}".strip() for item in items]
    try:
        vectorizer = TfidfVectorizer(
            lowercase=True,
            token_pattern=_TOKEN_PATTERN,
            stop_words=sorted(_STOPWORDS),
            sublinear_tf=True,
            norm="l2",
            max_features=max_vocab,
        )
        tfidf_sparse = vectorizer.fit_transform(documents)
    except ValueError:
        # Raised when the vocabulary ends up empty (every document empty or
        # entirely stopped-out). Tactic-only features still allow clustering.
        logger.warning(
            "cluster_gaps: TF-IDF vocabulary is empty (all documents empty or "
            "stopped-out); continuing with tactic-only features"
        )
        vocab: tuple[str, ...] = ()
        tfidf = np.zeros((len(documents), 0), dtype=np.float64)
    else:
        vocab = tuple(str(term) for term in vectorizer.get_feature_names_out())
        tfidf = np.asarray(tfidf_sparse.todense(), dtype=np.float64)

    one_hot = np.zeros((len(items), _N_TACTIC_DIMS), dtype=np.float64)
    for row, item in enumerate(items):
        tactic_position = _TACTIC_INDEX.get(item.tactic.strip().lower())
        if tactic_position is None:
            if item.tactic.strip():
                logger.debug(
                    "cluster_gaps: tactic %r not in the canonical list; "
                    "one-hot block left empty for %s",
                    item.tactic,
                    item.technique_attack_id,
                )
            continue
        one_hot[row, tactic_position] = _TACTIC_BLOCK_WEIGHT

    matrix = np.empty((len(items), _N_TACTIC_DIMS + tfidf.shape[1]), dtype=np.float64)
    matrix[:, :_N_TACTIC_DIMS] = one_hot
    matrix[:, _N_TACTIC_DIMS:] = tfidf
    return matrix, vocab


def _multi_clusters(
    items: Sequence[GapItem],
    matrix: np.ndarray,
    vocab: tuple[str, ...],
    labels: np.ndarray,
) -> tuple[GapCluster, ...]:
    """Build labelled clusters from raw k-means labels, canonically ordered."""
    members_by_label: dict[int, list[int]] = {}
    for index, label_value in enumerate(labels):
        members_by_label.setdefault(int(label_value), []).append(index)

    decorated: list[tuple[int, str, str, list[int]]] = []
    for members in members_by_label.values():
        tactic = _majority_tactic(members, items)
        tactic_rank = _TACTIC_INDEX.get(tactic, len(CANONICAL_TACTICS))
        smallest_id = min(items[i].technique_attack_id for i in members)
        decorated.append((tactic_rank, smallest_id, tactic, members))
    decorated.sort(key=lambda entry: (entry[0], entry[1]))

    clusters: list[GapCluster] = []
    tfidf_block = matrix[:, _N_TACTIC_DIMS:]
    for cluster_id, (_, _, tactic, members) in enumerate(decorated):
        clusters.append(
            _build_one_cluster(cluster_id, items, tfidf_block, vocab, members, tactic)
        )
    return tuple(clusters)


def _single_cluster(
    items: Sequence[GapItem],
    matrix: np.ndarray,
    vocab: tuple[str, ...],
) -> GapCluster:
    """Fallback cluster covering every item (no "outside" for keywords)."""
    members = list(range(len(items)))
    tactic = _majority_tactic(members, items)
    return _build_one_cluster(
        cluster_id=0,
        items=items,
        tfidf_block=matrix[:, _N_TACTIC_DIMS:],
        vocab=vocab,
        members=members,
        tactic=tactic,
    )


def _build_one_cluster(
    cluster_id: int,
    items: Sequence[GapItem],
    tfidf_block: np.ndarray,
    vocab: tuple[str, ...],
    members: Sequence[int],
    tactic: str,
) -> GapCluster:
    """Label and summarise one cluster of row indices into a :class:`GapCluster`."""
    ordered_members = sorted(members, key=lambda i: items[i].technique_attack_id)
    technique_ids = tuple(items[i].technique_attack_id for i in ordered_members)

    scores, mean_inside = _keyword_scores(tfidf_block, members)
    keywords = _select_keywords(scores, mean_inside, vocab)
    display_tactic = tactic if tactic.strip() else _UNTAGGED_TACTIC
    pair = "/".join(keywords)
    label = f"{display_tactic}: {pair}"
    summary = (
        f"{len(technique_ids)} undetected techniques cluster around {pair} "
        f"in the {display_tactic} tactic."
    )
    return GapCluster(
        cluster_id=cluster_id,
        label=label,
        technique_ids=technique_ids,
        summary=summary,
        size=len(technique_ids),
    )


def _keyword_scores(
    tfidf_block: np.ndarray,
    members: Sequence[int],
) -> tuple[np.ndarray, np.ndarray]:
    """Per-term ``(mean inside - mean outside)`` and ``mean inside`` scores.

    When there is no outside (single-cluster fallback) the outside mean is
    zero, making the distinguishing score equal to the mean-within score.
    """
    mask = np.zeros(tfidf_block.shape[0], dtype=bool)
    mask[list(members)] = True
    inside = tfidf_block[mask]
    outside = tfidf_block[~mask]
    n_terms = tfidf_block.shape[1]
    mean_inside = inside.mean(axis=0) if inside.shape[0] else np.zeros(n_terms, dtype=np.float64)
    mean_outside = outside.mean(axis=0) if outside.shape[0] else np.zeros(n_terms, dtype=np.float64)
    return mean_inside - mean_outside, mean_inside


def _select_keywords(
    scores: np.ndarray,
    mean_inside: np.ndarray,
    vocab: tuple[str, ...],
    limit: int = 2,
) -> list[str]:
    """Pick the top ``limit`` label keywords with deterministic tie-breaking.

    Terms whose distinguishing score exceeds :data:`_KEYWORD_MARGIN` win;
    remaining slots are padded from the highest mean-within terms and
    finally with :data:`_PLACEHOLDER_KEYWORD`.
    """
    def ranked(vector: np.ndarray) -> list[int]:
        return sorted(range(len(vocab)), key=lambda col: (-float(vector[col]), vocab[col]))

    chosen: list[str] = []
    taken: set[int] = set()
    for column in ranked(scores):
        if len(chosen) >= limit:
            break
        if float(scores[column]) > _KEYWORD_MARGIN:
            chosen.append(vocab[column])
            taken.add(column)
    if len(chosen) < limit:
        for column in ranked(mean_inside):
            if len(chosen) >= limit:
                break
            if column not in taken and float(mean_inside[column]) > 0.0:
                chosen.append(vocab[column])
                taken.add(column)
    while len(chosen) < limit:
        chosen.append(_PLACEHOLDER_KEYWORD)
    return chosen


def _majority_tactic(members: Sequence[int], items: Sequence[GapItem]) -> str:
    """Most frequent tactic among ``members``; ties break toward canonical order.

    Tactics are compared case-insensitively (mirroring contract B) and
    reported lowercased. Unknown tactics sort after the canonical ones,
    alphabetically among themselves.
    """
    counts: Counter[str] = Counter(items[i].tactic.strip().lower() for i in members)
    # Unknown tactics rank after all canonical ones (then alphabetically).
    winner = min(
        counts.items(),
        key=lambda kv: (-kv[1], _TACTIC_INDEX.get(kv[0], len(CANONICAL_TACTICS)), kv[0]),
    )
    return winner[0]


def _validated_int(
    section: Mapping[str, Any],
    key: str,
    default: int,
    *,
    minimum: int,
) -> int:
    """Read an integer config value, rejecting bools and values below minimum."""
    value = section.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"clustering.{key} must be an integer, got {value!r}")
    if value < minimum:
        raise ValueError(f"clustering.{key} must be >= {minimum}, got {value}")
    return value


def _validated_fraction(
    section: Mapping[str, Any],
    key: str,
    default: float,
) -> float:
    """Read a silhouette-threshold-style config value in ``(0.0, 1.0]``."""
    value = section.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"clustering.{key} must be a number, got {value!r}")
    threshold = float(value)
    if not 0.0 < threshold <= 1.0:
        raise ValueError(
            f"clustering.{key} must be in (0.0, 1.0], got {threshold}"
        )
    return threshold


def _validated_seed(
    section: Mapping[str, Any],
    key: str,
    default: int,
) -> int:
    """Read a RNG seed acceptable to scikit-learn's ``check_random_state``."""
    value = section.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"clustering.{key} must be an integer, got {value!r}")
    if not 0 <= value <= 2**32 - 1:
        raise ValueError(
            f"clustering.{key} must be in [0, 2**32 - 1] for a seeded "
            f"random_state, got {value}"
        )
    return value
