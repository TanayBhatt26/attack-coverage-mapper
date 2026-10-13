# ATT&CK Coverage Mapper

> **Given the log sources a team actually collects, which MITRE ATT&CK
> techniques can they detect — and which would let an attacker walk through
> undetected?**

ATT&CK Coverage Mapper is a Streamlit analytics dashboard layered on top of
[siem-log-parser](https://github.com/TanayBhatt26/siem-log-parser). It maps
real log formats and event types against MITRE ATT&CK Enterprise techniques,
scores coverage confidence using a DeTT&CT-informed rubric, simulates named
APT groups against configured coverage, clusters detection gaps, and generates
hunt queries (SigmaHQ-derived where possible).

Built as the course project for **Data Analytics & Visualization** (RRU SITAICS,
instructor-guided independent build by Tanay Bhatt).

---

## Table of Contents

- [Features](#features)
- [Demo Script](#demo-script)
- [Install \& Run](#install--run)
- [Project Layout](#project-layout)
- [How It Works](#how-it-works)
  - [Mapping Layer](#mapping-layer)
  - [Coverage Engine](#coverage-engine)
  - [APT Simulation](#apt-simulation)
  - [Hunt Query Generation](#hunt-query-generation)
  - [Gap Analysis](#gap-analysis)
- [Configuration](#configuration)
- [Performance Gates](#performance-gates)
- [Testing](#testing)
- [Reused vs. Original](#reused-vs-original)
- [Attribution](#attribution)
- [Out of Scope](#out-of-scope)
- [License](#license)

---

## Features

| Page | What it shows |
|------|---------------|
| **Coverage Overview** | Cividis heatmap of 14 canonical Enterprise tactics; KPI cards update as you toggle log sources |
| **APT Simulation** | Pick a named APT group → see detected / missed per tactic, greedy acquisition recommendations, missed-technique detail |
| **Hunt Queries** | One inert hunt query per missed technique, with colored source badges (community-sourced / hand-curated / generic) and full attribution |
| **Gap Analysis** | KMeans clustering of undetected techniques; each cluster shows which source toggle would close the gap |

---

## Demo Script (3–5 min)

1. **Baseline** — Open the Coverage Overview. Note the current coverage % (e.g. ~5% with the default Windows-scoped, evtx+json+cloudtrail+zeek config).
2. **Simulate APT** — Switch to APT Simulation, pick APT29, click *Run simulation*. Walk through the per-tactic bar chart and the recommended next sources.
3. **Hunt the gaps** — Switch to Hunt Queries. Expand a missed technique, point out the colored source badge and DRL 1.1 attribution block.
4. **Cluster view** — Switch to Gap Analysis. Open a cluster, show the "closable_by" source for each gap.
5. **Toggle a source** — Back to the sidebar, enable a previously disabled log source (e.g. `cef` or `syslog`). Coverage recomputes and the gap count drops.

---

## Install & Run

### Prerequisites

- Python 3.11–3.14
- Git
- (Optional) Docker Desktop — for the PostgreSQL parity checkpoint

### Setup

```bash
git clone https://github.com/TanayBhatt26/attack-coverage-mapper.git
cd attack-coverage-mapper

python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
# source .venv/bin/activate

pip install -r requirements.txt

# First run: the ATT&CK bundle is downloaded once and cached to data/attack_stix/
PYTHONPATH=src python -c "from src.attack_data.loader import load_all; load_all()"
```

### Run the Dashboard

```bash
PYTHONPATH=src streamlit run src/visualization/app.py
```

Then open the URL Streamlit prints (default: http://localhost:8501).

### Run Tests

```bash
PYTHONPATH=src .venv/Scripts/python.exe -m pytest -q          # Windows
PYTHONPATH=src .venv/bin/python -m pytest -q                  # macOS/Linux
```

Expected: **573+ passed, 1 skipped**.

---

## Project Layout

```
attack-coverage-mapper/
├── data/
│   ├── attack_mappings.csv        ← hand-curated mapping rules (the intellectual core)
│   ├── attack_stix/               ← cached MITRE ATT&CK STIX bundle
│   └── sample_logs/               ← 8 sample logs from the base repo
├── src/
│   ├── attack_data/               ← mitreattack-python wrapper, loader
│   ├── parser/                    ← LogEvent bridge, attack_mapper, siem_parsers
│   ├── detections/                ← Sigma index, hunt-query emitter
│   ├── database/                  ← SQLAlchemy models, session
│   ├── analysis/                  ← coverage engine, clustering, simulation
│   └── visualization/             ← Streamlit app + 4 views
├── tests/                         ← 573+ tests (unit + integration)
├── notebooks/                     ← exploratory analysis notebooks
├── config.yaml                    ← toggle log sources, threshold, scope
├── docker-compose.yml             ← PostgreSQL service (checkpoint use)
└── README.md
```

---

## How It Works

### Mapping Layer

`data/attack_mappings.csv` is the intellectual core of the project — 83
hand-curated rows mapping real `source_format` + `event_action` /
`extensions` patterns to ATT&CK technique IDs. Each row carries a
`base_confidence`, a `visibility_hint` (0–4, DeTT&CT-inspired), and an
`evidence_ref` linking back to a MITRE Detection Strategy (DET####) or
Analytic (AN####) object.

`src/parser/attack_mapper.py` applies a tiered matching scheme:

| Tier | Rule shape | Multiplier |
|------|-----------|------------|
| Extension-value rule | declares `ext_keys` + value pattern | ×1.00 |
| Action-only rule | declares `event_action_pattern` | ×0.85 |
| Heuristic rule | `match_type == 'heuristic'` | ×0.40 |

Capped at 0.95. A technique is **detectable** iff `best_confidence >=
threshold` (default 0.6, inclusive).

### Coverage Engine

`src/analysis/coverage_analyzer.py` materializes one `technique_coverage`
row per `(technique_stix_id, datasource_id)` pair for every enabled log
format, idempotently. The 14-bucket tactic rollup feeds the heatmap; the
gap list feeds the clustering and hunt-query emitters.

### APT Simulation

`src/analysis/simulation.py` runs a named APT group's techniques (loaded
from the ATT&CK `relationship` objects of type `uses`) through the
coverage engine. It reports detected / missed / roll-up counts, computes
per-tactic breakdowns, and emits greedy marginal-gain acquisition advice.

Verified against live ATT&CK data:

| Group | STIX ID | Techniques | Coverage |
|-------|---------|-----------|----------|
| APT29 | G0016 | 66 | 12.12% |
| APT41 | G0096 | 82 | 21.95% |
| Lazarus | G0032 | 93 | 16.13% |

### Hunt Query Generation

`src/detections/hunt_query_generator.py` emits exactly one inert hunt query
per missed technique (work-list invariant), by fixed precedence:

1. **hand-curated** — the M001–M020 core mapping set
2. **community-sourced** — a SigmaHQ rule converted via pySigma's
   `SplunkBackend` + `splunk_windows_pipeline`
3. **generic** — an `# UNREVIEWED` placeholder template

Every emitted query carries a DRL 1.1 attribution record (author, rule UUID,
GitHub permalink, license). Queries are inert text only — the module never
executes them.

### Gap Analysis

`src/analysis/gap_clustering.py` clusters undetected techniques by tactic
one-hot (weight 2) + TF-IDF KMeans, with silhouette k-selection and
deterministic seeding. Each cluster gets a human-readable label and a summary.

---

## Configuration

`config.yaml` drives the dashboard:

```yaml
platform_scope: windows
detection_confidence_threshold: 0.6

enabled_log_sources:
  evtx: true
  syslog: true
  cef: false
  leef: false
  json: true
  aws_cloudtrail: true
  nginx: false
  zeek: true
```

Toggle sources in the sidebar or edit `config.yaml` directly — coverage
recomputes on change.

---

## Performance Gates

| Gate | Budget | Measured |
|------|--------|----------|
| Full recompute (load + by-tactic + gaps + simulation) | < 5 s | ~0.06 s |
| Cached render path | < 3 s | < 0.01 s |

Enforced by `tests/test_performance.py`.

---

## Testing

```bash
# Full suite (offline)
PYTHONPATH=src .venv/Scripts/python.exe -m pytest -q

# Subsets
PYTHONPATH=src .venv/Scripts/python.exe -m pytest -m unit -q
PYTHONPATH=src .venv/Scripts/python.exe -m pytest -m integration -q
PYTHONPATH=src .venv/Scripts/python.exe -m pytest tests/test_performance.py -q
```

Markers: `unit` (no I/O), `integration` (filesystem/SQLite, offline),
`network` (live downloads — excluded in CI).

---

## Reused vs. Original

| Component | Source | What this project does |
|-----------|--------|------------------------|
| MITRE ATT&CK data | mitreattack-python (Apache-2.0) | Wraps the official library; ingests structured Detection Strategy / Analytics objects |
| Hunt queries | SigmaHQ rules (DRL 1.1) | Indexes by ATT&CK tag, converts via pySigma Splunk backend, attributes every export |
| Scoring rubric | DeTT&CT methodology (conceptual reference) | Adapts the visibility/data-quality tiers into the confidence formula |
| LogEvent schema | siem-log-parser (owner-authored, vendored with attribution header) | Adapted; geo/IP fields dropped, ATT&CK enrichment fields added |
| Base algorithms | scikit-learn, Plotly, Streamlit | Used as-is per their licenses |

| Component | Original to this project |
|-----------|--------------------------|
| `data/attack_mappings.csv` — 83 curated mapping rules | ✓ |
| `src/parser/attack_mapper.py` — tiered matcher | ✓ |
| `src/analysis/coverage_analyzer.py` — idempotent populate + gap analysis | ✓ |
| `src/analysis/gap_clustering.py` — KMeans gap clustering | ✓ |
| `src/analysis/simulation.py` — APT simulation engine | ✓ |
| `src/detections/hunt_query_generator.py` — hunt-query dispatch | ✓ |
| `src/visualization/` — Streamlit dashboard | ✓ |
| Confidence formula (DeTT&CT-attributed) | ✓ |

---

## Attribution

- **MITRE ATT&CK** — © The MITRE Corporation. ATT&CK is a trademark of
  MITRE. See [https://attack.mitre.org/resources/terms-of-use/](https://attack.mitre.org/resources/terms-of-use/).
- **mitreattack-python** — Apache-2.0, The MITRE Corporation & contributors.
- **SigmaHQ** — Detection Rule License (DRL) 1.1. See
  [https://github.com/SigmaHQ/Detection-Rule-License](https://github.com/SigmaHQ/Detection-Rule-License).
- **DeTT&CT** — MITRE (conceptual reference only; this project does not
  redistribute the DeTT&CT tooling).
- **scikit-learn** — BSD-3-Clause.
- **Streamlit** — Apache-2.0.
- **Plotly** — MIT.
- **siem-log-parser** — TanayBhatt26 (owner-authored, adapted and vendored
  with attribution; upstream published without a license file).

---

## Out of Scope

This project explicitly does **not**:

- Ingest logs from a live SIEM.
- Execute any hunt query against real systems.
- Build or distribute offensive tooling.
- Re-implement the DeTT&CT tooling.

All data used in the demo is synthetic or publicly available sample logs.

---

## License

This project's original code is licensed under the MIT License (see
`LICENSE`). Third-party components remain under their own licenses (see
[Attribution](#attribution)).
