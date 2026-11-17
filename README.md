# ATT&CK Coverage Mapper

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.62+-red.svg)](https://streamlit.io/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> **Coverage analytics for MITRE ATT&CK techniques** — Given your log sources, which techniques are detectable? Where are the gaps? What should you enable next?

---

## Overview

The **ATT&CK Coverage Mapper** transforms your log-source inventory into a quantitative, tactic-level coverage map against MITRE ATT&CK Enterprise techniques. It answers three questions:

1. **What can you detect?** — Tactic-level heatmap + per-technique confidence
2. **Where are the gaps?** — 575 gaps clustered by remediation action (enable source, acquire source, improve mappings)
3. **What should you do next?** — Hunt queries for every missed technique + greedy marginal-gain source recommendations

---

## Screenshots

### Coverage Overview
![Coverage Overview](docs/screenshots/coverage-overview.png)

### APT Simulation
![APT Simulation](docs/screenshots/apt-simulation.png)

### Hunt Queries
![Hunt Queries](docs/screenshots/hunt-queries.png)

### Gap Analysis
![Gap Analysis](docs/screenshots/gap-analysis-all.png)

---

## Quick Start

### Prerequisites
- Python 3.11+
- SQLite (default) or PostgreSQL 15+

### Installation
```bash
git clone https://github.com/your-org/attack-coverage-mapper.git
cd attack-coverage-mapper
python -m venv .venv
.venv/Scripts/activate    # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
```

### Run
```bash
# Terminal 1: Start Streamlit dashboard
PYTHONPATH=src .venv/Scripts/python.exe -m streamlit run src/visualization/app.py

# Terminal 2 (optional): Run Phase 7 demo
PYTHONPATH=src .venv/Scripts/python.exe scripts/run_phase7_demo.py G0016 -v
```

Open http://localhost:8501 in your browser.

### Data Initialization (optional)

The repository ships with a populated `db/coverage.db`, so a fresh clone opens a
working dashboard with no setup. The steps below rebuild that database from
source when you want to refresh the ATT&CK data, regenerate coverage, or add
SigmaHQ-backed hunt queries:

```bash
# 1. Ingest MITRE ATT&CK STIX data (Enterprise techniques + tactics)
PYTHONPATH=src .venv/Scripts/python.exe scripts/populate_db.py

# 2. Clone SigmaHQ rules (used for community-sourced hunt queries)
git clone --depth 1 https://github.com/SigmaHQ/sigma.git data/sigma

# 3. Run the Phase 7 demo to create simulation results
PYTHONPATH=src .venv/Scripts/python.exe scripts/run_phase7_demo.py G0016 -v
```

These three steps are idempotent and safe to re-run. The committed database is
a seed for a zero-install first run; `db/*.db` is gitignored, so your local
changes stay local.

---

## Architecture

```text
                           STREAMLIT DASHBOARD
      Coverage Overview | APT Simulation | Hunt Queries | Gap Analysis
                                    │
                                    ▼
                    ┌──────────────────────────────────────┐
                    │         ANALYSIS LAYER               │
                    │ Coverage Analyzer │ Gap Clustering   │
                    │ Simulation Engine  │ Remediation   │
                    └──────────────────────────────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────────────┐
                    │           PARSER LAYER               │
                    │ LogEvent Bridge │ Attack Mapper      │
                    │ Mappings I/O  │ SIEM Parsers         │
                    └──────────────────────────────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────────────┐
                    │           DATA LAYER                 │
                    │ SQLite/PostgreSQL │ ATT&CK STIX     │
                    │ Mappings CSV  │ Sigma Cache         │
                    └──────────────────────────────────────┘
```

### Key Modules

| Module | Purpose |
|--------|---------|
| `src/analysis/coverage_analyzer.py` | Load coverage rows, tactic rollup, gap calculation |
| `src/analysis/gap_clustering.py` | KMeans + TF-IDF clustering of gaps |
| `src/analysis/simulation.py` | APT group simulation + recommendations |
| `src/analysis/remediation.py` | Evidence-based gap classification |
| `src/detections/hunt_query_generator.py` | 3-tier hunt query dispatch (curated > Sigma > generic) |
| `src/detections/sigma_index.py` | Technique → Sigma rules index |
| `src/parser/attack_mapper.py` | Tiered mapping with confidence scoring |
| `src/visualization/views/*.py` | Four dashboard views |

---

## Configuration

Edit `config.yaml`:

```yaml
platform_scope: windows              # windows | linux | macos | all
detection_confidence_threshold: 0.6  # 0.0–1.0

# Sources the organization actually collects (for remediation classification)
collected_log_sources:
  - evtx
  - zeek

# Sources included in current coverage calculation (toggle in dashboard)
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

**Key distinction:** `enabled_log_sources` = analysis-time toggles (dashboard). `collected_log_sources` = operational inventory (for remediation classification).

**Deployment environment:** `APP_ENV` (default `development`) controls how strictly `DATABASE_URL` is resolved. In `production` it is mandatory and must be PostgreSQL. See [Deployment](#deployment-postgresql--streamlit-cloud).

---

## Deployment (PostgreSQL / Streamlit Cloud)

Streamlit Community Cloud mounts the repository **read-only**, so the SQLite
default cannot persist simulations there. Set `APP_ENV=production` and point
`DATABASE_URL` at a managed PostgreSQL database instead; the app then refuses to
start rather than silently falling back to a read-only file.

```bash
# one-time copy of the existing SQLite database into PostgreSQL
PYTHONPATH=src ./.venv/Scripts/python.exe scripts/migrate_sqlite_to_postgres.py \
    --postgres-url "postgresql+psycopg://user:password@host:5432/dbname" \
    --deep-verify
```

Streamlit Cloud Secrets:

```toml
APP_ENV = "production"
DATABASE_URL = "postgresql+psycopg://user:password@host:5432/dbname"
```

The migration is atomic, never drops anything, refuses a target that already
holds data, and re-synchronises the identity sequences so new simulations get
`max(id) + 1`. Local development is unaffected: with `APP_ENV` unset the app
still uses `db/coverage.db`.

Full guide, verification checklist and troubleshooting:
[docs/POSTGRESQL_DEPLOYMENT.md](docs/POSTGRESQL_DEPLOYMENT.md)

---

## Dashboard Views

### 1. Coverage Overview
- **Heatmap**: 14 ATT&CK tactics (Cividis colorscale)
- **KPIs**: In-scope, Detectable, Coverage %, Platform, Threshold
- **Estimated Addressable**: Per-source marginal gain (independent vs baseline)

### 2. APT Simulation
- Group picker (G0016 APT29, G0096 APT41, G0032 Lazarus)
- KPIs + per-tactic stacked bars
- Greedy marginal-gain recommendations
- Missed technique detail table

### 3. Hunt Queries
- Gap list (1 row = 1 missed technique, ASC order)
- Per-technique expander:
  - `st.code()` with copy widget
  - Colored badge: community-sourced / hand-curated / generic
  - Attribution block (DRL 1.1 for community)
  - Remediation link (source status → action)
  - UNREVIEWED header on generic queries

### 4. Gap Analysis
- **Remediation Bundles** (primary): Grouped by shared candidate sources
- **Tactic Groups**: Traditional ATT&CK tactic buckets
- **Exploratory KMeans**: Textual similarity clusters (secondary)
- **All Gaps**: Full table with remediation categories

---

## Coverage Scoring

```
Technique Score = max(enabled_sources) of:
    base_confidence × tier_multiplier

Tier multipliers:
  Extension-value match (tier 1):  1.00
  Action-pattern match (tier 2):   0.85
  Heuristic/format (tier 3):       0.40
  Cap: 0.95

Detectable ⇔ Technique Score ≥ threshold (default 0.6, inclusive)
```

**Important**: The score represents *mapping-based potential observability*, not the probability of detecting an actual attack. It assumes the mapped events exist and the SIEM rules fire correctly.

---

## Remediation Logic (Phase 7)

Each gap is classified into one category:

| Category | Trigger | Action |
|----------|---------|--------|
| `CANDIDATE_SOURCE_ENABLEMENT` | Collected but disabled source in `closable_by` | Enable in config |
| `POTENTIAL_SOURCE_ACQUISITION` | Not-collected source in `closable_by` | Evaluate acquisition |
| `SOURCE_STATUS_UNKNOWN` | `closable_by` source, inventory unknown | Investigate inventory |
| `REVIEW_EXISTING_SOURCE_MAPPINGS` | Enabled source contributes, score < 0.6 | Review mapping tier |
| `MAPPING_TELEMETRY_REVIEW` | Mappings exist, no candidate reaches threshold | Review mapping/telemetry |
| `MAPPING_COVERAGE_GAP` | No applicable mapping | Add mapping row |
| `DATA_QUALITY_ISSUE` | Enabled source in `closable_by` (invariant violation) | Investigate data quality |

---

## Hunt Query Attribution

| Source | License | Attribution |
|--------|---------|-------------|
| Hand-curated (M001–M020) | Project-original | ATT&CK Coverage Mapper |
| Community-sourced (SigmaHQ) | DRL 1.1 | Author, Rule ID, Repo URL, DRL 1.1 statement |
| Generic fallback | Template — not a detection rule | UNREVIEWED header |

---

## Limitations

| Limitation | Mitigation |
|------------|------------|
| Score ≠ detection probability | Model explicitly labeled "estimated coverage" |
| 5.12% coverage reflects mapping density | Add mappings; enable sources |
| 574/575 gaps have no closable source | Prioritize mapping work for high-value gaps |
| KMeans is exploratory | Primary view = Remediation Bundles (evidence-based) |
| Hunt queries are unvalidated templates | `UNREVIEWED` header on generic; DRL attribution on community |
| SigmaHQ clone not in repo | Clone with `git clone --depth 1 https://github.com/SigmaHQ/sigma.git data/sigma` |

---

## Data Sources & Attribution

| Asset | Source | License | Attribution |
|-------|--------|---------|-------------|
| MITRE ATT&CK Enterprise | MITRE | Apache-2.0 | MITRE ATT&CK © MITRE |
| MITRE ATT&CK Python | mitreattack-python | Apache-2.0 | mitreattack-python © MITRE |
| Sigma Rules | SigmaHQ | DRL 1.1 | SigmaHQ © authors, DRL 1.1 |
| pySigma | pySigma | LGPL-3.0 | pySigma contributors |
| Diskcache | diskcache | Apache-2.0 | Grant Jenks |

> **Residual vulnerability**: `diskcache==5.6.3` has CVE-2025-69872 (unsafe pickle deserialization). No patched version available. Risk is low (requires write access to cache directory). Ensure cache directory is not writable by untrusted processes.

---

## Testing

```bash
# Full suite (595 passed, 0 failed, 7 skipped)
PYTHONPATH=src .venv/Scripts/python.exe -m pytest -q

# Core tests only (excludes golden-data integration)
PYTHONPATH=src .venv/Scripts/python.exe -m pytest tests/test_remediation.py tests/test_hunt_view.py tests/test_dashboard_views.py -q

# Validation report
PYTHONPATH=src .venv/Scripts/python.exe scripts/validate_coverage.py
```

---

## Reproducibility

```bash
# Clean clone test
git clone https://github.com/your-org/attack-coverage-mapper.git
cd attack-coverage-mapper
python -m venv .venv
.venv/Scripts/activate
pip install -r requirements.txt
PYTHONPATH=src python -m pytest -q
# Expected: 595 passed, 0 failed, 7 skipped
```

All tests pass on a fully populated clone. The 7 skipped tests require optional dependencies
not installed in the base environment (diskcache, Playwright).

---

## Roadmap

- [x] Phase 8: README, screenshots, validation report
- [x] Phase 9: Demo script (`scripts/run_phase7_demo.py`, `scripts/demo.py`), clean-clone rehearsal (test suite green on fresh tree)
- [x] Phase 10: Viva question bank (`docs/VIVA_QUESTIONS.md`), pip-audit (documented; `pip-audit` not installed in venv — prior results in SAVE_STATE.md), license review (README attribution table + LICENSE)

---

## License

MIT License — see [LICENSE](LICENSE)

---

## Citation

If you use this work, please cite:

```
@software{attack_coverage_mapper,
  title = {ATT&CK Coverage Mapper},
  author = {Tanay Bhatt},
  year = {2026},
  url = {https://github.com/your-org/attack-coverage-mapper}
}
```