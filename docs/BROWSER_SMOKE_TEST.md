# Browser Smoke Test Checklist

Run: `streamlit run src/visualization/app.py`

## Pre-checks
- [ ] Database connected banner shows green (SQLite or Postgres)
- [ ] Config sidebar visible on left
- [ ] Page navigation radio buttons visible: Coverage Overview, APT Simulation, Hunt Queries, Gap Analysis

---

## View 1: Coverage Overview
- [ ] Page title: "Coverage Overview"
- [ ] KPI row shows 5 metrics: In-scope, Detectable, Coverage %, Platform scope, Threshold
- [ ] Plotly heatmap renders with 14 tactics (reconnaissance → impact)
- [ ] Heatmap colors use Cividis scale
- [ ] Hover shows tactic name, detectable/total, percentage
- [ ] "Tactic detail" expander opens with table (tactic, detectable, total, coverage)
- [ ] Config sidebar: toggle `zeek` off → heatmap updates, coverage decreases
- [ ] Config sidebar: toggle `zeek` back on → heatmap reverts

---

## View 2: APT Simulation
- [ ] Page title: "APT Simulation"
- [ ] Sidebar group picker defaults to G0016 (APT29)
- [ ] "Run simulation" button executes
- [ ] KPI row: Total=66, Detected=6, Rollup=2, Missed=58, Coverage=12.12%
  - **Note**: Coverage = (Detected + Rollup) / Total = (6+2)/66 = 12.12%
- [ ] Per-tactic stacked bar chart renders (detected=#, missed=#)
- [ ] Recommendations section shows at least one bullet
- [ ] "Missed techniques" expander opens with table (technique, name, tactic, confidence, sources)
- [ ] Change group to G0096 → run → KPIs update
- [ ] Change group to G0032 → run → KPIs update

---

## View 3: Hunt Queries
- [ ] Page title: "Hunt — missed techniques"
- [ ] Sidebar: "Simulation result id" defaults to latest
- [ ] Gap list table: columns = technique_attack_id, query_language, attribution_label, source_rule_id, closable_by, confidence
- [ ] Row count = missed_count (58 for G0016)
- [ ] Expander for T1190 (or any): opens with `st.code` block showing SPL query
- [ ] Query has colored badge: generic / hand-curated / community-sourced
- [ ] Generic queries show "UNREVIEWED" warning
- [ ] "Attribution" section visible below query
- [ ] Generic: shows "License: template — not a detection rule"
- [ ] Community-sourced: shows title, author, rule_id, repo_url, DRL 1.1 license, statement
- [ ] Hand-curated: shows "Author: ATT&CK Coverage Mapper", "License: project-original"
- [ ] Remediation link below attribution: shows candidate sources with status/action
- [ ] Code block has copy button (built-in Streamlit)
- [ ] Click through all 58 expanders — no errors

---

## View 4: Gap Analysis
- [ ] Page title: "Gap Analysis"
- [ ] KPI row: Total gaps=575, With candidate source=1, Unresolved=574, Data quality issues=0
- [ ] Tab 1 "Remediation Bundles": shows bundles grouped by candidate sources
  - [ ] Bundle "nginx (not_collected)" with 1 technique (T1190)
- [ ] Tab 2 "Tactic Groups": 14 expanders, one per tactic
  - [ ] Each shows techniques with name, confidence, closable_by
- [ ] Tab 3 "Exploratory KMeans": clusters with labels and technique lists
  - [ ] Caption about exploratory nature visible
- [ ] Tab 4 "All Gaps": full table with remediation category column
  - [ ] Remediation category column matches: CANDIDATE_SOURCE_ENABLEMENT, POTENTIAL_SOURCE_ACQUISITION, etc.

---

## Config Sidebar
- [ ] Header: "Configuration"
- [ ] Checkboxes for all 8 log sources: evtx, syslog, cef, leef, json, aws_cloudtrail, nginx, zeek
- [ ] Toggle `zeek` off → success toast "config.yaml updated" → page reruns → coverage decreases
- [ ] Toggle `zeek` back on → coverage reverts
- [ ] `collected_log_sources` displayed (read-only caption)
- [ ] Platform scope and threshold shown as read-only captions

---

## Cross-cutting
- [ ] No JavaScript errors in browser console
- [ ] No Python tracebacks in terminal
- [ ] Page switches are fast (< 2s)
- [ ] Responsive layout on different window sizes
- [ ] Dark/light theme works (if applicable)

---

## Sign-off
- [ ] All checks passed
- [ ] Screenshots captured for README
- [ ] Any issues documented

Date: __________  Tester: __________