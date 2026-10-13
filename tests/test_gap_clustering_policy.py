"""Policy-contract tests for ``analysis.gap_clustering`` (Phase 3, Wave 2).

Black-box tests pinning the Wave-2 agreed clustering contract exactly:

* ``GapItem(technique_attack_id, name, tactic, description)`` -- frozen,
  hashable, tuple-only fields (hashability contract A applied to inputs).
* ``cluster_gaps(...) -> tuple[GapCluster, ...]`` where ``GapCluster`` is a
  frozen dataclass with fields ``cluster_id:int, label:str,
  technique_ids:tuple, summary:str, size:int`` (contract F).
* Policy: ``n == 0`` -> ``()``; ``n <= 3`` -> one cluster, no KMeans;
  ``n >= 4`` -> sweep ``k`` in ``range(2, min(k_max, n // 2) + 1)``, pick the
  best mean silhouette, accept iff ``s >= silhouette_threshold`` AND every
  cluster holds ``>= 2`` members, else fall back to a single cluster
  (NaN silhouette falls back too).
* Labels follow ``'{majority tactic}: {top-2 distinguishing keywords}'``
  (keyword = highest mean-TF-IDF-in-cluster minus mean-outside, ``> 0.05``);
  summaries are one sentence starting ``'<n> undetected techniques'`` and
  naming both keywords plus the majority tactic.
* Real-world conservatism: research/p3-wave1-full-results.md:351 measured
  max silhouette 0.168 over the real ~449-gap set, so the policy returning
  ONE cluster there is CORRECT behaviour. The mechanism is tested directly
  (raising the threshold forces a single cluster on otherwise-separable
  data); a 449-item realistic mimic is smoke-tested for structural
  invariants only -- its exact partition is intentionally NOT asserted
  because synthetic text cannot reproduce the measured 0.168.

Decisions taken under contract freedom:

* The implementation may use sklearn ``TfidfVectorizer`` or a hand-rolled
  TF-IDF; these tests stay black-box and observe tokenisation effects
  (stopword exclusion, ``[a-z0-9]{3,}`` boundaries incl. 3-char and digit
  tokens) through cluster labels instead of internals.
* Config plumbing is probed, not guessed: sibling code lands in parallel,
  so :func:`call_cluster_gaps` inspects ``cluster_gaps``' signature once
  and tries canonical payload shapes -- a declared dataclass params object
  constructed from the override kwargs first, then mapping payloads
  (full config ``{"clustering": ...}`` vs flat options dict). The winning
  shape must *behaviourally* honour ``silhouette_threshold=0.99`` by
  flipping a separable probe set to one cluster, so a silently ignored
  override fails loudly instead of yielding green-but-meaningless tests.
* Cross-process byte-identity is delegated to the seeded KMeans
  (``random_state=cfg seed``, ``n_init=10``) and is deliberately not
  verified here: spawning subprocesses is banned in this wave.

All inputs are synthetic pure-python tuples; nothing touches the database,
filesystem or network (classified ``unit`` in pyproject markers).
"""

from __future__ import annotations

import dataclasses
import inspect
import logging
import re
from collections import Counter
from typing import Any, Callable, Sequence, get_args, get_type_hints

import pytest

from analysis.gap_clustering import GapCluster, GapItem, cluster_gaps

logger = logging.getLogger(__name__)

# Pure functions, zero I/O -> "unit" marker per pyproject.toml.
pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Contract constants
# ---------------------------------------------------------------------------

#: Exact public field surface pinned by the Wave-2 contract (order matters
#: for positional construction).
GAP_ITEM_FIELDS = ["technique_attack_id", "name", "tactic", "description"]
GAP_CLUSTER_FIELDS = ["cluster_id", "label", "technique_ids", "summary", "size"]

#: Stopword floor from contract F; implementations may extend the set, so
#: tests only assert that THESE never surface as extracted keywords.
STOPWORD_FLOOR = frozenset(
    {"technique", "adversaries", "may", "using", "windows", "attack", "system"}
)

#: Canonical Enterprise tactic order (contract D/F reference; used here only
#: to spread the scale-smoke mimic realistically).
CANONICAL_TACTICS = (
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


# ---------------------------------------------------------------------------
# Synthetic gap builders
# ---------------------------------------------------------------------------

#: Three keyword-disjoint themes. Each theme contributes exactly two
#: consistently-present keywords (document frequency = all theme items,
#: absent elsewhere) so those two are deterministically the top-2
#: distinguishing keywords of their cluster; fillers vary per item and stay
#: weaker. Keyword choice deliberately probes tokenizer boundaries:
#: ``8080`` (digit token), ``rpc`` / ``dns`` (3-char lower bound).
THEMES: dict[str, dict[str, tuple[str, ...]]] = {
    "credential-access": {
        "keywords": ("kerberos", "ticket"),
        "fillers": ("dcsync", "lsass", "hash", "secret", "domain", "dump"),
    },
    "command-and-control": {
        "keywords": ("beacon", "8080"),
        "fillers": ("covenant", "listener", "channel", "sleep", "jitter", "socket"),
    },
    "exfiltration": {
        "keywords": ("rpc", "dns"),
        "fillers": ("archive", "upload", "compress", "staging", "drive", "share"),
    },
}

#: Distinct attack-id ranges per theme keep ids collision-free.
_THEME_ID_BASE = {
    "credential-access": 9101,
    "command-and-control": 9201,
    "exfiltration": 9301,
}


def make_gap(
    technique_attack_id: str,
    tactic: str,
    name: str = "Synthetic gap technique",
    description: str = "Adversaries may do a synthetic thing using tools",
) -> GapItem:
    """Build one :class:`GapItem` positionally-faithful to the contract."""
    return GapItem(
        technique_attack_id=technique_attack_id,
        name=name,
        tactic=tactic,
        description=description,
    )


def theme_items(tactic: str, count: int) -> list[GapItem]:
    """Build ``count`` items of one keyword-disjoint theme (same tactic)."""
    keywords = THEMES[tactic]["keywords"]
    fillers = THEMES[tactic]["fillers"]
    base = _THEME_ID_BASE[tactic]
    kw1, kw2 = keywords
    items = []
    for i in range(count):
        filler = fillers[i % len(fillers)]
        items.append(
            GapItem(
                technique_attack_id=f"T{base}.{i:03d}",
                name=f"{kw1} {kw2} operations",
                tactic=tactic,
                description=(
                    f"Adversaries may {kw1} {kw2} using {filler} on host {i}"
                ),
            )
        )
    return items


def three_theme_thirty() -> list[GapItem]:
    """The classic acceptance fixture: 30 items, 3 disjoint themes."""
    items: list[GapItem] = []
    for tactic in THEMES:
        items.extend(theme_items(tactic, 10))
    return items


def noise_items(count: int, tactic: str = "execution") -> list[GapItem]:
    """Fully degenerate items: text tokenises to NOTHING and the tactic
    one-hot block is constant, so every feature row is the zero vector.

    Exercises the named edge case "empty-tokenised technique -> zero vector
    must still cluster (and degrade conservatively)". For a variant that
    keeps *distinct* tactics (tactic-block signal only), build GapItems
    directly -- see ``test_textless_items_may_group_by_tactic``.
    """
    return [
        GapItem(
            technique_attack_id=f"T99{i:03d}",
            name="? ? ?",
            tactic=tactic,
            description="may using system technique",
        )
        for i in range(count)
    ]


def mimic_449() -> list[GapItem]:
    """A 449-item realistic-text mimic of the current real gap set.

    Tactics cycle over all 14 Enterprise tactics; texts reuse a small pool
    of realistic ATT&CK-flavoured vocabulary (shared corpus, weak structure)
    mirroring how the real ~449 gaps look to the featuriser. Structural
    invariants only are asserted -- see module docstring.
    """
    texts = (
        "valid accounts logon session credential domain",
        "scheduled task service execution command script interpreter",
        "registry run key startup folder persistence autostart",
        "os credential dumping lsass kerberos ticket hash capture",
        "remote system discovery network share connection sweep",
        "web service command channel encrypted protocol sleep",
        "archive collected data compress staging transfer cloud",
    )
    return [
        GapItem(
            technique_attack_id=f"T8000.{i:03d}",
            name=texts[i % len(texts)],
            tactic=CANONICAL_TACTICS[i % len(CANONICAL_TACTICS)],
            description=f"{texts[(i + 3) % len(texts)]} on endpoint",
        )
        for i in range(449)
    ]


# ---------------------------------------------------------------------------
# Shared assertions
# ---------------------------------------------------------------------------

def tactic_map(gaps: Sequence[GapItem]) -> dict[str, str]:
    """Map attack-id -> tactic for a gap sequence."""
    return {g.technique_attack_id: g.tactic for g in gaps}


def assert_valid_partition(
    clusters: Any,
    gaps: Sequence[GapItem],
    *,
    expect_single: bool = False,
) -> None:
    """Assert every structural invariant the contract guarantees.

    Checks: result is a ``tuple`` of :class:`GapCluster`; ``technique_ids``
    is a tuple of str; ``size == len(technique_ids)``; members form an exact,
    duplicate-free partition of the input ids; cluster ids are unique ints;
    and (optionally) that exactly one cluster was returned.
    """
    assert isinstance(clusters, tuple), (
        f"cluster_gaps must return a tuple, got {type(clusters).__name__}"
    )
    assert all(isinstance(c, GapCluster) for c in clusters)
    if expect_single:
        assert len(clusters) == 1, (
            f"expected single-cluster fallback, got {len(clusters)} clusters"
        )

    seen: list[str] = []
    for cluster in clusters:
        assert isinstance(cluster.technique_ids, tuple), (
            "technique_ids must be a tuple (hashability contract)"
        )
        assert all(isinstance(t, str) for t in cluster.technique_ids)
        assert isinstance(cluster.cluster_id, int)
        assert cluster.size == len(cluster.technique_ids), (
            f"size {cluster.size} != len(technique_ids) "
            f"{len(cluster.technique_ids)}"
        )
        seen.extend(cluster.technique_ids)

    assert len({c.cluster_id for c in clusters}) == len(clusters), (
        "cluster_id values must be unique"
    )
    expected = sorted(g.technique_attack_id for g in gaps)
    assert sorted(seen) == expected, "members must exactly cover the input ids"
    assert len(seen) == len(set(seen)), "an id appeared in more than one cluster"


def _norm(text: str) -> str:
    """Alphanumerics-only lowercase normalisation for tolerant matching."""
    return re.sub(r"[^a-z0-9]+", "", text.lower())


# ---------------------------------------------------------------------------
# Config-plumbing adapter (parallel-development seam)
# ---------------------------------------------------------------------------

_PROBE_STATE: dict[str, Any] = {}


def _ordinary_params_after_first() -> list[inspect.Parameter]:
    """Signature parameters of ``cluster_gaps`` after the gap-items argument."""
    params = list(inspect.signature(cluster_gaps).parameters.values())
    return [p for p in params[1:] if p.kind is not inspect.Parameter.VAR_KEYWORD]


def _dataclass_annotation(param: inspect.Parameter) -> type | None:
    """Return the parameter's dataclass type when one is declared.

    Resolves string annotations (``from __future__ import annotations``
    modules) via :func:`typing.get_type_hints` and unwraps ``Optional[X]`` /
    ``X | None`` unions. Returns ``None`` when no dataclass is in play.
    """
    try:
        hints = get_type_hints(cluster_gaps)
    except Exception as exc:  # unresolvable forward refs etc.
        logger.debug("get_type_hints(%r) failed: %s", cluster_gaps, exc)
        return None
    hint = hints.get(param.name)
    for candidate in get_args(hint) or (hint,):
        if isinstance(candidate, type) and dataclasses.is_dataclass(candidate):
            return candidate
    return None


def _positional_caller(payload: Any) -> Callable[[Sequence[GapItem]], Any]:
    """Caller passing ``payload`` as the second positional argument."""
    return lambda gaps: cluster_gaps(gaps, payload)


def _keyword_caller(name: str, payload: Any) -> Callable[[Sequence[GapItem]], Any]:
    """Caller passing ``payload`` under keyword ``name``."""
    return lambda gaps: cluster_gaps(gaps, **{name: payload})


def _probe_separable_baseline() -> list[GapItem]:
    """12-item 2-theme probe set; default call must split it (>1 cluster)."""
    probe = theme_items("credential-access", 6) + theme_items(
        "command-and-control", 6
    )
    baseline = cluster_gaps(probe)
    if not (isinstance(baseline, tuple) and len(baseline) > 1):
        raise AssertionError(
            "internal probe fixture failed: a 12-item two-disjoint-theme set "
            f"did not separate under defaults (got {len(baseline)} cluster(s)); "
            "config-override tests cannot run"
        )
    return probe


def _override_shapes(
    overrides: dict[str, Any],
) -> list[tuple[str, Callable[[Sequence[GapItem]], Any]]]:
    """Enumerate plausible ways to hand ``overrides`` to ``cluster_gaps``.

    Priority order: a declared dataclass parameter constructed from the
    override kwargs (positional, then keyword-by-name), then mapping-style
    payloads -- full config ``{"clustering": {...}}`` first, flat options
    dict last -- each positional then keyword. Every entry is a ready
    callable over a gap sequence; wrong shapes raise ``TypeError`` when the
    probe invokes them.
    """
    ordinary = _ordinary_params_after_first()
    calls: list[tuple[str, Callable[[Sequence[GapItem]], Any]]] = []

    if ordinary:
        first = ordinary[0]
        dc_type = _dataclass_annotation(first)
        if dc_type is not None:
            try:
                params_obj = dc_type(**overrides)
            except TypeError as exc:
                logger.debug("dataclass %s rejects overrides: %s", dc_type, exc)
            else:
                calls.append((
                    f"dataclass {dc_type.__name__}(**overrides) positional",
                    _positional_caller(params_obj),
                ))
                calls.append((
                    f"dataclass {dc_type.__name__}(**overrides) keyword {first.name!r}",
                    _keyword_caller(first.name, params_obj),
                ))
        for style_desc, payload in (
            ("full-config {'clustering': {...}}", {"clustering": dict(overrides)}),
            ("flat clustering options dict", dict(overrides)),
        ):
            calls.append((f"{style_desc} positional", _positional_caller(payload)))
            calls.append((
                f"{style_desc} keyword {first.name!r}",
                _keyword_caller(first.name, payload),
            ))
    else:
        calls.append((
            "var-keyword expansion",
            lambda gaps: cluster_gaps(gaps, **overrides),
        ))
    return calls


def _resolve_override_caller() -> Callable[[Sequence[GapItem]], Any]:
    """Find (and cache) HOW to pass clustering overrides to ``cluster_gaps``.

    The sibling implementation lands in parallel, so the exact cfg plumbing
    (dataclass params vs mapping payloads; positional vs keyword) is
    discovered once, empirically: each candidate caller must *behaviourally*
    honour ``silhouette_threshold=0.99`` on the separable probe set
    (forcing one cluster). A caller that raises ``TypeError`` (wrong shape)
    or silently ignores the override therefore cannot win the probe.
    """
    if "caller" in _PROBE_STATE:
        cached = _PROBE_STATE["caller"]
        if isinstance(cached, AssertionError):
            raise cached
        return cached  # type: ignore[return-value]

    probe = _probe_separable_baseline()
    failures: list[str] = []
    for desc, caller in _override_shapes({"silhouette_threshold": 0.99}):
        try:
            result = caller(probe)
        except TypeError as exc:
            failures.append(f"{desc}: TypeError({exc})")
            continue
        if isinstance(result, tuple) and len(result) == 1:
            logger.debug("Override plumbing resolved via %s", desc)

            def cached_caller(
                gaps: Sequence[GapItem],
                overrides: dict[str, Any],
                _desc: str = desc,
            ) -> Any:
                matches = _override_shapes(overrides)
                for match_desc, match_call in matches:
                    if match_desc == _desc:
                        return match_call(gaps)
                raise AssertionError(
                    f"cfg plumbing shape {_desc!r} disappeared while rebuilding "
                    f"with overrides {sorted(overrides)}; candidates were "
                    f"{[d for d, _ in matches]}"
                )

            _PROBE_STATE["caller"] = cached_caller
            return cached_caller
        failures.append(
            f"{desc}: override ignored "
            f"(got {len(result)} clusters, expected forced single)"
        )

    error = AssertionError(
        "could not resolve cluster_gaps cfg plumbing: no candidate honoured "
        "silhouette_threshold=0.99 on the separable probe set. Signature "
        f"params after the gap-items argument: "
        f"{[p.name for p in _ordinary_params_after_first()]}. Tried:\n  - "
        + "\n  - ".join(failures)
    )
    _PROBE_STATE["caller"] = error
    raise error


def call_cluster_gaps(
    gaps: Sequence[GapItem], **overrides: Any
) -> tuple[GapCluster, ...]:
    """Call ``cluster_gaps`` with contract-named clustering overrides.

    With no ``overrides`` this is the canonical dashboard call shape
    ``cluster_gaps(gaps)`` (defaults apply). Overrides use the documented
    config keys: ``min_clusterable``, ``k_max``, ``silhouette_threshold``,
    ``max_vocab``, ``seed``.
    """
    if not overrides:
        result = cluster_gaps(gaps)
        assert isinstance(result, tuple)
        return result
    caller = _resolve_override_caller()
    result = caller(gaps, dict(overrides))
    assert isinstance(result, tuple)
    return result

# ---------------------------------------------------------------------------
# Dataclass contracts (frozen / hashable / exact field surface)
# ---------------------------------------------------------------------------


class TestGapItemContract:
    """GapItem: exact field surface, frozen, hashable."""

    def test_field_names_and_order(self) -> None:
        assert [f.name for f in dataclasses.fields(GapItem)] == GAP_ITEM_FIELDS

    def test_frozen_hashable_equality(self) -> None:
        gap_a = make_gap("T1003", "credential-access", name="OS Credential Dumping")
        gap_b = make_gap("T1003", "credential-access", name="OS Credential Dumping")
        gap_c = make_gap("T1003", "credential-access", description="different")
        assert gap_a == gap_b and hash(gap_a) == hash(gap_b)
        assert gap_a != gap_c
        # Usable in hash-based containers (cache/st.cache_data contract).
        assert len({gap_a, gap_b, gap_c}) == 2
        with pytest.raises(dataclasses.FrozenInstanceError):
            gap_a.name = "mutated"  # type: ignore[misc]


class TestGapClusterContract:
    """GapCluster: exact field surface, frozen, hashable, size consistency."""

    def test_field_names_and_order(self) -> None:
        assert [f.name for f in dataclasses.fields(GapCluster)] == GAP_CLUSTER_FIELDS

    def test_result_tuple_of_frozen_hashable_clusters(self) -> None:
        result = cluster_gaps(theme_items("credential-access", 2))
        assert_valid_partition(result, theme_items("credential-access", 2))
        cluster = result[0]
        with pytest.raises(dataclasses.FrozenInstanceError):
            cluster.label = "mutated"  # type: ignore[misc]
        # Hash-stable outputs (st.cache_data native-hash guarantee).
        frozenset(result)
        assert hash(cluster) == hash(result[0])


# ---------------------------------------------------------------------------
# Trivial-input policy (n == 0 and n <= 3: no KMeans, single cluster)
# ---------------------------------------------------------------------------


class TestTrivialInputs:
    @pytest.mark.parametrize("count", [0, 1, 2, 3])
    def test_n_below_min_clusterable(self, count: int) -> None:
        gaps = noise_items(count) if count else []
        result = cluster_gaps(tuple(gaps))
        assert isinstance(result, tuple)
        if count == 0:
            assert result == ()
        else:
            assert_valid_partition(result, gaps, expect_single=True)

    def test_accepts_list_and_tuple_input_identically(self) -> None:
        items = three_theme_thirty()
        assert cluster_gaps(list(items)) == cluster_gaps(tuple(items))

    def test_input_sequence_not_mutated(self) -> None:
        items = three_theme_thirty()
        snapshot = list(items)
        cluster_gaps(items)
        assert items == snapshot


# ---------------------------------------------------------------------------
# Single-cluster fallback policy (guards + threshold + degenerate features)
# ---------------------------------------------------------------------------


class TestSingleClusterFallback:
    def test_zero_vector_items_still_yield_one_cluster(self) -> None:
        """All-zero feature rows (no text tokens, constant tactic) must not
        crash and must degrade to the conservative single-cluster outcome
        (NaN / sub-threshold silhouette fallback)."""
        gaps = noise_items(6)
        result = cluster_gaps(tuple(gaps))
        assert_valid_partition(result, gaps, expect_single=True)

    def test_textless_items_may_group_by_tactic(self) -> None:
        """Empty-text items whose TACTICS differ still carry one-hot signal,
        so grouping them by tactic is legitimate implementation latitude.
        Only the structural invariants are contractual here."""
        gaps = [
            GapItem(
                technique_attack_id=f"T98{i:03d}",
                name="? ? ?",
                tactic=tactic,
                description="may using system technique",
            )
            for i, tactic in enumerate(
                ("execution", "persistence", "discovery") * 2
            )
        ]
        result = cluster_gaps(tuple(gaps))
        assert_valid_partition(result, gaps)

    def test_threshold_above_silhouette_forces_single_cluster(self) -> None:
        """Accept iff s >= threshold ELSE fallback -- the exact mechanism
        behind the real-world 449-gap single-cluster verdict (measured max
        silhouette 0.168 < 0.20, research/p3-wave1-full-results.md:351).
        Raising the bar to 0.99 must collapse even perfectly separable
        themes into one cluster."""
        gaps = three_theme_thirty()
        result = call_cluster_gaps(gaps, silhouette_threshold=0.99)
        assert_valid_partition(result, gaps, expect_single=True)

    def test_fallback_label_and_summary_are_nonempty_sentences(self) -> None:
        gaps = noise_items(6)
        cluster = cluster_gaps(tuple(gaps))[0]
        assert isinstance(cluster.label, str) and cluster.label.strip()
        assert isinstance(cluster.summary, str) and cluster.summary.strip()
        assert cluster.summary.rstrip().endswith(".")


# ---------------------------------------------------------------------------
# Successful multi-cluster behaviour
# ---------------------------------------------------------------------------


class TestSuccessfulClustering:
    def test_three_disjoint_themes_yield_three_pure_clusters(self) -> None:
        gaps = three_theme_thirty()
        result = cluster_gaps(gaps)
        assert_valid_partition(result, gaps)
        assert len(result) == 3, (
            f"expected 3 theme clusters, got {len(result)}: "
            f"{[c.label for c in result]}"
        )
        tactic_of = tactic_map(gaps)
        for cluster in result:
            assert cluster.size >= 2, "every accepted cluster needs >= 2 members"
            member_tactics = {tactic_of[tid] for tid in cluster.technique_ids}
            assert len(member_tactics) == 1, (
                f"cluster {cluster.cluster_id} mixed tactics: {member_tactics}"
            )

    def test_labels_follow_majority_tactic_keyword_format(self) -> None:
        gaps = three_theme_thirty()
        result = cluster_gaps(gaps)
        tactic_of = tactic_map(gaps)
        matched_tactics: set[str] = set()
        for cluster in result:
            members_tactic = next(iter({
                tactic_of[tid] for tid in cluster.technique_ids
            }))
            matched_tactics.add(members_tactic)
            keywords = THEMES[members_tactic]["keywords"]
            # Tolerates slug ('credential-access:') vs title ('Credential
            # Access: ...') rendering via alphanumeric normalisation.
            assert _norm(cluster.label).startswith(_norm(members_tactic)), (
                f"label {cluster.label!r} does not lead with majority tactic "
                f"{members_tactic!r}"
            )
            lowered = cluster.label.lower()
            for keyword in keywords:
                assert keyword in lowered, (
                    f"distinguishing keyword {keyword!r} missing from label "
                    f"{cluster.label!r}"
                )
            # Stopword floor must never be mined as a keyword.
            label_tokens = set(re.findall(r"[a-z0-9]{3,}", lowered))
            assert not label_tokens & STOPWORD_FLOOR, (
                f"stopwords surfaced as keywords in label {cluster.label!r}"
            )
        assert matched_tactics == set(THEMES)

    def test_summaries_are_contract_sentences(self) -> None:
        gaps = three_theme_thirty()
        result = cluster_gaps(gaps)
        tactic_of = tactic_map(gaps)
        for cluster in result:
            members_tactic = next(iter({
                tactic_of[tid] for tid in cluster.technique_ids
            }))
            keywords = THEMES[members_tactic]["keywords"]
            summary = cluster.summary.strip()
            assert summary.endswith("."), f"not sentence-terminated: {summary!r}"
            assert summary.startswith(f"{cluster.size} undetected techniques"), (
                f"summary must open '<n> undetected techniques', got {summary!r}"
            )
            lowered = summary.lower()
            for keyword in keywords:
                assert keyword in lowered, (
                    f"keyword {keyword!r} missing from summary {summary!r}"
                )
            assert _norm(members_tactic) in _norm(lowered), (
                f"majority tactic {members_tactic!r} missing from summary "
                f"{summary!r}"
            )

    def test_two_theme_eight_items_split_evenly(self) -> None:
        gaps = theme_items("credential-access", 4) + theme_items(
            "command-and-control", 4
        )
        result = cluster_gaps(gaps)
        assert_valid_partition(result, gaps)
        assert sorted(c.size for c in result) == [4, 4]

    def test_token_boundary_keywords_reach_labels(self) -> None:
        """3-char tokens (``rpc``, ``dns``) and digit tokens (``8080``) are
        valid ``[a-z0-9]{3,}`` features and must be eligible distinguishing
        keywords."""
        gaps = three_theme_thirty()
        result = cluster_gaps(gaps)
        tactic_of = tactic_map(gaps)
        for cluster in result:
            members_tactic = next(iter({
                tactic_of[tid] for tid in cluster.technique_ids
            }))
            lowered = cluster.label.lower()
            for keyword in THEMES[members_tactic]["keywords"]:
                assert keyword in lowered

    def test_k_max_override_caps_the_sweep(self) -> None:
        """k in range(2, min(k_max, n // 2) + 1): k_max=2 leaves only k=2,
        so three themes must merge into exactly two accepted clusters."""
        gaps = three_theme_thirty()
        result = call_cluster_gaps(gaps, k_max=2)
        assert_valid_partition(result, gaps)
        assert len(result) == 2, (
            f"k_max=2 must cap the sweep at k=2, got {len(result)} clusters"
        )


# ---------------------------------------------------------------------------
# Determinism and seeding
# ---------------------------------------------------------------------------


class TestDeterminismAndSeeding:
    def test_repeated_calls_byte_identical(self) -> None:
        gaps = three_theme_thirty()
        first = cluster_gaps(gaps)
        second = cluster_gaps(gaps)
        assert first == second
        assert repr(first) == repr(second)

    def test_explicit_seed_is_repeatable(self) -> None:
        gaps = three_theme_thirty()
        assert call_cluster_gaps(gaps, seed=7) == call_cluster_gaps(gaps, seed=7)


# ---------------------------------------------------------------------------
# Config surface
# ---------------------------------------------------------------------------


class TestConfigSurface:
    def test_default_call_without_cfg_argument(self) -> None:
        """Dashboard contract: ``cluster_gaps(gaps)`` alone must work with
        documented defaults (min_clusterable=4, k_max=6, threshold=0.2,
        max_vocab=200, seed=42)."""
        gaps = three_theme_thirty()
        result = cluster_gaps(gaps)
        assert_valid_partition(result, gaps)
        assert len(result) >= 1

    def test_overrides_are_honoured_not_silently_dropped(self) -> None:
        """Behavioural proof that cfg values reach the algorithm: with three
        themes the default sweep may accept up to k=6, but k_max=2 must cap
        the outcome at exactly two clusters (the threshold flip is asserted
        in TestSingleClusterFallback)."""
        gaps = three_theme_thirty()
        capped = call_cluster_gaps(gaps, k_max=2)
        assert_valid_partition(capped, gaps)
        assert len(capped) == 2


# ---------------------------------------------------------------------------
# Real-world scale smoke (structural invariants only)
# ---------------------------------------------------------------------------


class TestRealWorldScaleSmoke:
    def test_449_item_mimic_partitions_validly(self) -> None:
        """Smoke the real-world gap-set scale (449 items). The measured
        reality (research/p3-wave1-full-results.md:351) is ONE conservative
        cluster at max silhouette 0.168; synthetic text cannot reproduce that
        number, so ONLY structural invariants are asserted here -- any
        partition count is acceptable, none may violate the contract."""
        gaps = mimic_449()
        result = cluster_gaps(gaps)
        assert_valid_partition(result, gaps)
        assert all(c.size >= 2 or len(result) == 1 for c in result), (
            "accepted multi-cluster splits must hold >= 2 members each"
        )
