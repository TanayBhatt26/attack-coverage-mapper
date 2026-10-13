# Mapping Methodology — ATT&CK Coverage Mapper

**Artifact:** `data/attack_mappings.csv` (curated mapping catalog) consumed by `src/parser/attack_mapper.py`
**Phase:** 2 — Mapping layer · **Date:** 2026-08-26
**Audience:** maintainers, reviewers, and the viva committee. This document specifies *why* the mapping layer looks the way it does and *exactly* how a normalized log event becomes an ATT&CK technique annotation with a calibrated confidence score.

---

## 1. Purpose and scope

The coverage mapper answers one question per collected log source: *"Which MITRE ATT&CK Enterprise techniques can this source plausibly evidence?"* It does so by evaluating each parsed `LogEvent` against a hand-curated catalog of mapping rules and annotating the event with:

- `attack_technique_ids` — distinct techniques matched,
- `attack_tactics` — sorted union of the tactics of the kept matches,
- `datasource_type` — static per-format data-source label,
- `detection_confidence` — the strongest match score for the event.

Out of scope for this stage: cross-event correlation (burst/spray aggregation), SIEM query generation, and coverage arithmetic (Phase 3's `coverage_analyzer.py`). The mapper is deliberately single-event and deterministic: identical inputs always produce identical annotations.

## 2. Design principles

1. **Evidence hierarchy over keyword soup.** A technique claim backed by a specific field value (e.g. `NewProcessName = ...\powershell.exe`) is stronger than one inferred from the event label alone. The tier system encodes this directly in the score.
2. **Conservative by construction.** Generic, noisy signals are scored *below* the detectability threshold (default 0.6) so coverage percentages are not inflated by baseline traffic. Weak signals stay *visible* (annotated) but are not counted as detections.
3. **Every claim carries provenance.** Each row links to a MITRE technique page, a SigmaHQ rule, or both (`evidence_ref`, `sigma_rule_id`), plus a free-text rationale in `notes`.
4. **Fail loudly at load time, never at match time.** Catalog validation happens once, up front, naming the offending row; the matching engine itself never raises on data.
5. **Attributed reuse.** The confidence rubric is conceptually derived from DeTT&CT's visibility/data-quality scoring (attributed reference per the project spec); ATT&CK terminology follows MITRE's usage guidelines.

## 3. Pipeline position

```
raw log ──► siem_parsers.parse_log_content(content, fmt)      (adapted base-repo parsers)
              └─► List[LogEvent]
                    └─► attack_mapper.map_log_event(event, rules, config)
                          ├─ candidates = rules where rule.source_format == event.source_format
                          ├─ tiered matching + scoring + dedupe
                          └─► mutated LogEvent (techniques / tactics / datasource / confidence)
                                └─► database / coverage_analyzer / dashboard
```

Rules come from `parser.mappings_io.load_mappings(path)`; configuration from `config_loader.load_config(path="config.yaml")`. Imports resolve with `PYTHONPATH=src`; no library module mutates `sys.path`.

## 4. Inputs

### 4.1 LogEvent (enrichment view)

Matching reads only `source_format`, `event_action`, and `extensions` (plus the config gate). Extensions are a free-form `dict[str, Any]`: for EVTX, EventData name/value pairs are merged **verbatim in original casing**, and the Windows Event ID lives *only* in `extensions["event_id"]`; for CloudTrail the parser always populates `{aws_region, event_source, event_type, error_code, error_message, request_id, user_type, account_id, request_params}`. `category` is never populated by the EVTX adapter and plays no role in matching.

### 4.2 Mapping catalog schema — `attack_mappings.csv`

Parsed with `csv.DictReader`; exactly **14 columns** are expected. 83 curated rows (`M001`–`M083`); `M001`–`M020` form the flagship **core set** (`is_core=true`).

| Column | Type | Semantics |
|---|---|---|
| `mapping_id` | str | Unique rule ID (`M\d+` convention). Duplicates rejected. |
| `source_format` | str | One of `syslog, cef, leef, json, evtx, aws_cloudtrail, nginx, zeek`. Anything else rejected. |
| `event_action_pattern` | regex or empty | Matched with `re.fullmatch` against `event.event_action`. **Empty cell ⇒ no action matching for this rule** (rule becomes extension-driven). `^…$` anchors are redundant under `fullmatch` but kept intentionally — they document intent. |
| `ext_keys` | space-separated keys or empty | Ordered candidate keys into `event.extensions`, compared **case-insensitively** (values keep original casing/values). Empty tuple ⇒ rule cannot use Tier 1. |
| `ext_value_pattern` | regex or empty | Applied via `.search()` to `str(value)` of the **first** `ext_key` found present in the event. Empty cell ⇒ presence alone suffices. **`match_type=exists` overrides this column**: the loader discards any value pattern, so presence of the key alone matches (the cell then documents the expected content only). |
| `match_type` | enum | `exact` \| `regex` \| `exists` \| `heuristic`. Semantic labels: `exact` = dedicated, unambiguous event type; `regex` = value/pattern discrimination; `exists` = key presence; `heuristic` = weak format-level prior (see §5.2 Tier 3). |
| `is_core` | bool | Case-insensitive `true/false`. Core rows drive hand-written hunt queries and the planned Atomic Red Team validation. |
| `technique_id` | str | Validated against `^T\d{4}(\.\d{3})?$`. |
| `tactic` | str | Lowercase kebab ATT&CK tactic (e.g. `credential-access`). |
| `base_confidence` | float | Prior confidence in `[0, 1]` (§6). Out-of-range rejected. |
| `visibility_hint` | int | DeTT&CT-style visibility 0–4 (reporting/UI hint; feeds the rubric in §6). Out-of-range rejected. |
| `evidence_ref` | str | MITRE technique URL or SigmaHQ rule URL — mandatory provenance pointer. |
| `sigma_rule_id` | UUID or empty | Community Sigma rule the row was informed/adapted from, where applicable. |
| `notes` | str | Analyst rationale, including deliberate false-positive trade-offs. |

Any violation — unknown format, uncompilable regex, bad technique ID, duplicate ID, out-of-range number, wrong column count — makes `load_mappings` raise `ValueError` naming the offending `mapping_id`/row. Regexes are compiled once at load, so bad patterns fail before any event is seen.

## 5. Matching algorithm (normative)

### 5.1 Candidate selection

Candidates are the rules with `rule.source_format == event.source_format`. Rules for other formats are never consulted.

### 5.2 Tiered evaluation

For each candidate, at most one tier applies, selected by the rule's shape:

| Tier | Condition | Multiplier |
|---|---|---|
| **1 — Extension** | `len(rule.ext_keys) > 0` **and** any key of `ext_keys` is present in `{k.lower(): v for k, v in event.extensions.items()}` **and** (`ext_value_re is None` or it matches `str(value)` of the first found key) **and** — when the rule declares an `event_action_pattern` — that pattern also `fullmatch`es `event.event_action or ""`. The action gate scopes *which events* a rule applies to; without it, exists-style rows (e.g. `M010`) would leak onto every logon carrying `TargetUserName`. | `base × 1.0` |
| **2 — Action** | `len(rule.ext_keys) == 0` **and** `event_action_re is not None` **and** it `fullmatch`es `event.event_action or ""` | `base × 0.85` |
| **3 — Format-level weak** | Evaluated **only when Tiers 1–2 produced zero matches across all candidates**: rule has `match_type == "heuristic"` and passes whichever ext/action predicate it declares | `base × 0.40` |

Rationale for the ordering and penalties:

- **Tier 1** is field-grounded evidence: the event *says* something specific (a binary name, an NTSTATUS code, an IAM error). Full credit.
- **Tier 2** relies on the event label alone; adapters normalize labels well (EVTX `EVENTID_MAP`, CloudTrail `eventName`, Zeek notices), but labels omit discriminating context, hence the −15%.
- **Tier 3** exists so that weak, format-level priors can annotate events carrying no stronger evidence anywhere in the catalog. Its 0.40 multiplier guarantees such results sit far below the detectability threshold (max 0.40 < 0.6): visible for gap analysis, never counted as a detection.

Helper: `score_for_tier(base_confidence, tier)` returns the multiplied score — the single place the multipliers live.

### 5.3 Scoring, capping, deduplication

1. Every computed score is **capped at 0.95** — even a definitive indicator (e.g. security-audit log cleared) stops short of claimed certainty.
2. Multiple rules may map to the same technique (e.g. `M002` plain PowerShell spawn and `M004` download-cradle both claim `T1059.001`). Scores are deduplicated **per `technique_id`, keeping the highest-scoring rule**; the loser's tactic contributes nothing.
3. Distinct techniques are **union-preserved** — one event can legitimately attest several techniques (a Root `StopLogging` matches `M016` → `T1562.008` *and* `M049` → `T1078.004`).
4. `event.attack_tactics` = sorted union of the tactics of the kept rules; `event.detection_confidence` = the highest kept score (the event's best evidence).

### 5.4 Disabled sources

If `config.enabled_log_sources.get(fmt)` is `False`, matching is skipped entirely: `attack_technique_ids` and `attack_tactics` are cleared and `detection_confidence` reset to `0.0`, but `datasource_type` is retained. Toggling a source off therefore visibly drains coverage in the dashboard without corrupting the data-source inventory. Configuration shape: `{platform_scope: str, detection_confidence_threshold: float, enabled_log_sources: {fmt: bool}}`; `load_config` fills sane defaults (threshold **0.6**) and lets a missing file raise `FileNotFoundError` naturally.

## 6. Confidence model (DeTT&CT-attributed)

`base_confidence` is not a gut feeling; each row's value is derived from a rubric conceptually attributed to **DeTT&CT**'s visibility/data-quality scoring:

```
C = 0.55 · (visibility / 4)          # how clearly the source shows the behavior
  + 0.30 · data-quality factor        # fidelity of the emitting telemetry
  + 0.15 · field-discrimination factor# how specifically the mapped fields separate signal from noise
 (+0.10 if backed by a structured ATT&CK Detection Strategy object)
```

The resulting prior is stored per rule; the `visibility_hint` column retains the 0–4 visibility input for reporting. At runtime, the tier multiplier (§5.2) discounts the prior when the actual event evidence is weaker than the curated assumption. A technique is **detectable ⇔ confidence ≥ threshold** (default 0.6, inclusive).

**Why 0.6:** dedicated, unambiguous events — purpose-built Windows Event IDs (`4698` task created), explicit Zeek analyzer notices (`SSH::Bruteforcing`), IAM mutations — clear the bar, while generic noisy actions (baseline `4624` logons, `IPC$` share touches, `whoami.exe` spawns) sit below it until corroborating fields appear. This keeps reported coverage honest: weak signals remain visible in the data but never inflate the detection percentage.

## 7. Datasource typing

`datasource_type` is a **static, code-owned mapping** (not a CSV column) applied to every event regardless of match outcome:

| `source_format` | `datasource_type` |
|---|---|
| `evtx` | `windows:eventlog` |
| `syslog` | `linux:syslog` |
| `cef` / `leef` | `network:device` |
| `json` | `generic:json` |
| `aws_cloudtrail` | `cloud:cloudtrail` |
| `nginx` | `web:access` |
| `zeek` | `network:zeek` |
| anything else | `unknown:<fmt>` |

Coverage rows are keyed `(technique_id, datasource_id)` downstream, so this label is what ties a detected technique back to the log source proving it.

## 8. Parser vocabularies the catalog relies on

Mappings were written against the exact output shapes of the adapted base-repo parsers:

| Format | `event_action` | Notes used by mappings |
|---|---|---|
| `evtx` | One of 20 `EVENTID_MAP` enums (`logon_success`, `logon_failure`, `process_created`, `new_service_installed`, `audit_log_cleared`, …) | EventData merged verbatim (original casing); Event ID only in `extensions["event_id"]`; IDs outside the map fall back to `EventID-<id>` (exploited by `M043` for 5145 pipe accesses). |
| `aws_cloudtrail` | `eventName` verbatim (`ConsoleLogin`, `StopLogging`, …) | Extensions always contain the nine fixed keys incl. `error_code`, `request_params`, `user_type`. |
| `zeek` | `conn` → conn-state code or `connection`; `http` → `<METHOD> <status>`; `dns` → `DNS <qtype> query`; `notice` → note enum verbatim (`SSH::Bruteforcing`); `weird` → empty string | Action regexes encode these shapes (`^POST \d{3}$`, `^DNS TXT query$`). |
| `syslog` | APP-NAME free-form (TAG fallback) | e.g. `sudo[1234]`, `cron`. |
| `nginx` | `<METHOD> <status>` | Path probing judged via `http_path`. |
| `cef` / `leef` / `json` | Vendor text / normalized ECS-style actions | Kept coarse and low-scored; vendor heterogeneity. |

## 9. The curated catalog

83 rows spanning all eight supported formats:

| Format | Rows | Character |
|---|---|---|
| `evtx` | 41 | Deepest coverage: credential access, execution cradles, persistence (services/tasks/accounts), lateral movement (RDP/admin shares), defense evasion (log clearing, tool tampering), discovery. |
| `aws_cloudtrail` | 18 | Control-plane abuse: failed console auth, logging impairment, key/policy manipulation, public-bucket exposure, recon verb bursts. |
| `zeek` | 15 | Network-layer: SSH brute-force notices, scan proxies, DNS tunneling/TOR/mining, web exfil POSTs, proxy CONNECT. |
| `syslog` / `cef` / `leef` / `json` / `nginx` | 2+2+1+2+2 | Deliberately conservative priors; vendor text varies too much for high confidence without per-deployment tuning. |

12 distinct tactics are represented (execution, persistence, privilege-escalation, credential-access, lateral-movement, defense-evasion, collection, discovery, impact, command-and-control, exfiltration, initial-access). Match types: predominantly `regex`, with `exact` for dedicated event types, `exists` for presence-only claims, and `heuristic` reserved for knowingly weak priors (each flagged in `notes`, e.g. `M056` RunInstances-UserData is FP-heavy because IaC embeds UserData legitimately).

Representative rows:

| ID | Fires when | Technique | Base |
|---|---|---|---|
| `M001` | EVTX `logon_failure` | `T1110.001` password guessing | 0.60 |
| `M004` | `process_created` + CommandLine cradle (download + IEX) | `T1059.001` | 0.75 |
| `M014` | EVTX `audit_log_cleared` (1102) | `T1070.001` | 0.95 |
| `M015` | CloudTrail `ConsoleLogin` with any `error_code` | `T1110` | 0.70 |
| `M016` | `StopLogging`/`DeleteTrail` on the CloudTrail service | `T1562.008` | 0.90 |
| `M019`/`M020` | Zeek SSH password-guessing / bruteforce notices | `T1110.001` | 0.85 / 0.90 |
| `M053` | Bucket policy/Acl setting a wildcard principal | `T1530` | 0.85 |

## 10. Worked examples (real sample logs)

**EVTX `sample.evtx.xml`**

- *Bare 4625 failed logon:* `M001` has no `ext_keys`, so it matches at **Tier 2** → `0.60 × 0.85 = 0.51`. Annotated, **below** threshold — a single failed logon must not read as brute force. (`M024` adds NTSTATUS discrimination on `substatus`/`status` for a stronger Tier-1 claim.)
- *4688 spawning PowerShell:* `M002` (`NewProcessName` regex) hits **Tier 1** → `0.70`. If the command line also contains a download-cradle, `M004` scores `0.75` and **wins the dedupe** for `T1059.001`.

**CloudTrail `sample.aws.json`**

- *Failed `ConsoleLogin`* (`errorCode: Failed authentication`): `M015` Tier 1 on `error_code` → `0.70` ⇒ detectable.
- *Root `StopLogging`:* `M016` Tier 1 (`request_params`-adjacent `event_source` check) → `0.90`, and `M049` (`user_type = Root`, action-independent) → `0.70`. Two distinct techniques kept; tactics union `[defense-evasion]`; `detection_confidence = 0.90`.

**Zeek `sample.zeek.log`**

- *`SSH::Password_Guessing` notice:* `M019` Tier 2 → `0.85 × 0.85 ≈ 0.72` ⇒ detectable; the stronger `M020` bruteforce notice reaches `≈ 0.77`.

## 11. Validation and failure modes

- **Load time (strict):** all guarantees of §4.2. Tests exercise each rejection path with `tmp_path` catalogs.
- **Match time (total):** unknown/malformed events simply match nothing — no exceptions, no silent format fallback (the parser adapter raises `ValueError` for unknown formats instead).
- **Determinism:** no randomness, no clock, no network in the matching path; `LogEvent.event_id` (a random uuid4) is never used as a matching key.

## 12. Limitations and deferred work

- **Single-event horizon:** spray/slow-brute-force and burst-recon need cross-event aggregation; affected rows (`M012`, `M040`, `M057`, `M058`) are scored as weak priors and say so in `notes`.
- **Known false-positive posture:** generic rows (`M021` baseline logon, `M042` IPC$, `M027` file-object access) are intentionally sub-threshold corroboration, not detections.
- **Empirical grounding pending:** Atomic Red Team validation of 3–5 core mappings in an isolated VM is a scheduled human step; until then confidence rests on the rubric and parser-verified vocabularies.
- **ATT&CK version drift:** technique/tactic validity tracks the ingested STIX bundle snapshot recorded in the database meta row; the catalog references stable technique IDs but is reviewed when ATT&CK deprecations land.

## 13. References and attribution

- MITRE ATT&CK Enterprise knowledge base — technique pages linked per-row in `evidence_ref`; ATT&CK and ATT&CK Navigator usage per MITRE's terms.
- DeTT&CT — conceptual source of the visibility/data-quality confidence rubric (attributed reference, not reused code).
- SigmaHQ rule set — provenance UUIDs in `sigma_rule_id`; licensing obligations tracked at export time (Phase 5).
- Base parsers adapted from `github.com/TanayBhatt26/siem-log-parser` (owner-authored upstream, no license file; local adaptations carry attribution headers).
