# Viva Question Bank — ATT&CK Coverage Mapper

General questions a panel might ask during a viva/defense, organized by topic area.

## 1. Project Overview

**Q1. What is the ATT&CK Coverage Mapper?**

It's a Streamlit dashboard that maps MITRE ATT&CK techniques against log-source coverage. Given which log sources an organization collects (e.g., EVTX Windows Event Logs, AWS CloudTrail, Zeek network logs), it maps those sources to ATT&CK techniques using curated mapping rules, scores each technique's detectability on a 0–1 scale, identifies coverage gaps, simulates APT groups against the coverage, and generates hunt queries for missed techniques.

**Q2. Why is this useful?**

Security teams collect log data but often don't know which ATT&CK techniques their telemetry can actually detect. The mapper bridges that gap by mapping real log sources to ATT&CK techniques, scoring coverage, identifying gaps, and generating hunt queries for undetected techniques.

**Q3. What are the five main views?**

1. **Coverage Overview** — 14-bucket tactic heatmap with per-technique confidence scoring and an estimated-attack-surface panel showing which disabled sources could close which gaps.
2. **APT Simulation** — Simulate a named APT group (APT29/G0016, APT41/G0096, Lazarus/G0032) against current coverage; see detected vs. missed per technique with greedy marginal-gain acquisition recommendations.
3. **Hunt Queries** — One inert hunt query per missed technique, with attribution labels (hand-curated / community-sourced / generic), source badges, copy-to-clipboard queries, and remediation links.
4. **Gap Analysis** — Undetected techniques organized into Remediation Bundles (grouped by shared candidate sources), Tactic Groups, exploratory KMeans clustering, and a full gap table.

---

## 2. Architecture & Implementation

**Q4. What is the overall architecture?**

Four layers:

1. **Data Layer** — SQLite database (or PostgreSQL via docker-compose) storing ATT&CK STIX data, mapping rules, simulation results, and technique coverage rows.
2. **Parser Layer** — LogEvent bridge, attack_mapper (tiered matching), mappings I/O, SIEM parsers for 8 log formats (EVTX, syslog, CEF, LEEF, JSON, AWS CloudTrail, Nginx, Zeek).
3. **Analysis Layer** — coverage_analyzer (load coverage rows, tactic rollup, gap calculation), gap_clustering (KMeans + TF-IDF), simulation (APT attack simulation + recommendations), remediation (evidence-based gap classification).
4. **Visualization Layer** — Streamlit dashboard with five views (Coverage Overview, APT Simulation, Hunt Queries, Gap Analysis, Anomaly Detection).

**Q5. What data does the system consume?**

- ATT&CK Enterprise STIX bundle (techniques, tactics, relationships)
- `attack_mappings.csv` — 83 curated mapping rules linking log sources + event patterns to ATT&CK techniques
- Simulation results stored in SQLite

**Q6. What is the confidence scoring model?**

For each technique, the mapper computes:

```
Technique Score = max(enabled sources) of (base_confidence × tier_multiplier)
```

Tier multipliers:
- Extension-value match (tier 1): 1.00
- Action-pattern match (tier 2): 0.85
- Heuristic/format match (tier 3): 0.40
- Cap: 0.95

A technique is detectable if best_confidence ≥ threshold (default 0.6).

**Q7. What data does the system consume?**
- ATT&CK STIX Enterprise bundle (techniques, tactics, groups, relationships)
- `attack_mappings.csv` — 83 curated mappings with technique IDs, source formats, event patterns, base confidences, tier multipliers
- Simulation results stored in SQLite (technique_techniques table)

**Q8. Why are there 858 techniques but only 606 in-scope?**

858 is the total number of ATT&CK techniques in the loaded STIX bundle (v19). 697 are non-revoked (alive). Of those, 606 match the configured platform scope (Windows). 161 are revoked/deprecated, and 91 are out of platform scope.

**Q9: How does the simulation work?**

`simulate_apt_attack(group_id)`:
1. Loads the group's techniques from `apt_technique` (joined to `techniques`, non-revoked only)
2. For each technique, looks up `technique_coverage` rows for enabled sources
3. Classifies each technique: detected (best confidence ≥ threshold), detected_rollup (sub-technique of detected parent, or parent with detectable child), or missed
4. Persists a `SimulationResult` row with total/detected/missed/coverage_pct and per-technique rows

**Q10: How does the hunt-query generator work?**

`export_all_queries(result_id)`:
1. Reads missed SimulationTechnique rows (ordered by attack_id ASC)
2. Re-derives `closable_by` via `calculate_coverage_gaps`
3. Dispatches one query per missed technique by precedence:
   - hand-curated (M001–M020 core set)
   - SigmaHQ match (pySigma SplunkBackend + splunk_windows_pipeline)
   - generic fallback (UNREVIEWED placeholder template)
4. Persists each query to `technique_coverage` and returns an ordered dict keyed by technique_attack_id

---

## 3. Security & Data

**Q9: What data sources does the system support?**

Eight log formats: EVTX (Windows Event Log), syslog, CEF, LEEF, JSON (ECS/JSON), AWS CloudTrail, Nginx, Zeek.

**Q10: What is the DRL 1.1 license?**

The Detection Rule License 1.1 is SigmaHQ's license for Sigma rules. It requires retaining author attribution, linking to the rule set, and stating DRL 1.1 licensing when sharing rules. The view displays this attribution for community-sourced (SigmaHQ-derived) queries.

**Q13: What security controls does the app have?**

- All queries are inert text (no execution)
- Community-sourced rules are clearly marked as such with DRL attribution
- Generic queries are marked "UNREVIEWED"
- No secrets are stored in config; database URL is from environment
- No secrets or API keys are stored in the repo

---

## 4. Code Quality & Testing

**Q14: How is the code tested?**

Pytest with 626 passing tests, 0 failed, 12 skipped (optional dependencies and a live PostgreSQL target not present in the base environment).

**Q15: How is reproducibility ensured?**

- All dependencies pinned in `requirements.txt`
- Config-driven (not hardcoded)
- Deterministic clustering (seed=42)
- Deterministic dispatch ordering
- Clean clone works: clone, venv, pip install, pytest passes

---

## 5. Limitations & Honest Assessment

**Q16: What are the project's limitations?**

| Limitation | Mitigation |
|------------|------------|
| Coverage score ≠ detection probability | Model explicitly labeled "estimated coverage" |
| 5.12% coverage reflects mapping density | Add mappings; enable sources |
| 574/575 gaps have no closable source | Prioritize mapping work for high-value gaps |
| KMeans is exploratory | Primary view = Remediation Bundles (evidence-based) |
| Hunt queries are unvalidated templates | `UNREVIEWED` header on generic; DRL attribution on community |
| SigmaHQ clone not in repo | Clone with `git clone --depth 1 https://github.com/SigmaHQ/sigma.git data/sigma` |

**Q17: What is original vs. reused?**

| Component | Source | What this project adds |
|-----------|--------|------------------------|
| ATT&CK data | mitreattack-python (Apache-2.0) | Wraps official library; ingests structured Detection Strategy/Analytics objects |
| Hunt queries | SigmaHQ rules (DRL 1.1) | Indexes by ATT&CK tag, converts via pySigma Splunk backend, attributes every export |
| Scoring rubric | DeTT&CT methodology (conceptual reference) | Adapts visibility/data-quality tiers into confidence formula |
| LogEvent schema | siem-log-parser (owner-authored) | Adapted; ATT&CK enrichment fields added |
| Base algorithms | scikit-learn, Plotly, Streamlit | Used as-is per licenses |
| Mappings CSV (83 rows) | Original | Hand-curated mapping rules |
| Curated hunt queries | Original | Hand-written SPL queries for core techniques |
| Remediation classification | Original | Evidence-based gap classification into 7 categories |

---

## 6. Operations & Deployment

**Q18: How do I run the dashboard?**

```bash
git clone https://github.com/your-org/attack-coverage-mapper.git
cd attack-coverage-mapper
python -m venv .venv
.venv/Scripts/activate   # Windows
# source .venv/bin/activate  # Linux/macOS
pip install -r requirements.txt
PYTHONPATH=src .venv/Scripts/python.exe -m streamlit run src/visualization/app.py
```

**Q19: How do I run the demo?**

```bash
PYTHONPATH=src .venv/Scripts/python.exe scripts/run_phase7_demo.py G0016 -v
```

This runs coverage overview, APT simulation for G0016 (APT29), hunt queries, and gap analysis in the terminal.

**Q20: How do I validate coverage?**

```bash
PYTHONPATH=src .venv/Scripts/python.exe scripts/validate_coverage.py
```

This produces a `validation_report.json` with the coverage breakdown.

---

**End of README**