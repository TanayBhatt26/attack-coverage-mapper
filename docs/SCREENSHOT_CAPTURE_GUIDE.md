# Screenshot Capture Guide

Run: `streamlit run src/visualization/app.py` → open http://localhost:8501

## Screenshots to Capture

| # | View | Filename | What to Capture |
|---|------|----------|-----------------|
| 1 | Coverage Overview | `coverage-overview.png` | Full page: KPI row (5 metrics), Cividis heatmap (14 tactics), Estimated Addressable panel |
| 2 | APT Simulation | `apt-simulation.png` | After running G0016: KPI row, per-tactic stacked bars, recommendations, missed techniques table |
| 3 | Hunt Queries | `hunt-queries.png` | Gap list (58 rows) + one expanded expander with code block, badge, attribution, remediation link |
| 4 | Gap Analysis - Bundles | `gap-analysis-bundles.png` | Remediation Bundles tab expanded (nginx bundle with T1190) |
| 5 | Gap Analysis - Tactic | `gap-analysis-tactic.png` | Tactic Groups tab (14 tactic expanders) |
| 6 | Gap Analysis - KMeans | `gap-analysis-kmeans.png` | Exploratory KMeans tab (clusters with labels) |
| 7 | Gap Analysis - All | `gap-analysis-all.png` | All Gaps tab (full table with remediation category) |
| 8 | Config Toggle | `config-toggle-before.png` | Sidebar before toggle (zeek **enabled**); record original coverage |
| 9 | Config Toggle | `config-toggle-after.png` | Sidebar after toggle (zeek **disabled**); show updated coverage |

## Capture Instructions

1. Start app: `PYTHONPATH=src .venv/Scripts/python.exe -m streamlit run src/visualization/app.py`
2. Open http://localhost:8501
3. Run G0016 simulation in APT Simulation view
4. Capture each view as specified above
5. For config toggle:
   - Start with **zeek enabled** (default)
   - Screenshot `config-toggle-before.png` with original coverage
   - Toggle **zeek off** → wait for rerun
   - Screenshot `config-toggle-after.png` with updated coverage
   - Toggle zeek **back on** to restore original config

## File Naming
Save to `docs/screenshots/` with exact filenames above.