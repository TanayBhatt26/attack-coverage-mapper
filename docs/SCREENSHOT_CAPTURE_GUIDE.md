# Screenshot Capture Guide

Run: `streamlit run src/visualization/app.py` → open http://localhost:8501

## Screenshots to Capture

| # | View | Filename | What to Capture |
|---|------|----------|-----------------|
| 1 | Coverage Overview | `coverage-overview.png` | Full page: KPI row (5 metrics), Cividis heatmap (14 tactics), Estimated Addressable panel |
| 2 | APT Simulation | `apt-simulation.png` | After running G0016: KPI row, per-tactic stacked bars, recommendations, missed techniques table |
| 3 | Hunt Queries | `hunt-queries.png` | Gap list (58 rows) + one expanded expander with code block, badge, attribution, remediation link |
| 4 | Gap Analysis — Bundles | `gap-analysis.png` | Remediation Bundles tab |
| 5 | Gap Analysis — All | `gap-analysis-all.png` | All Gaps tab (full table with remediation category) |
| 6 | Anomaly Detection | `anomaly-detection.png` | KPI row + events table + anomaly-score scatter |
| 7 | Config Toggle | `config-toggle-before.png` | Sidebar with **zeek enabled** (coverage 5.12%) |
| 8 | Config Toggle | `config-toggle-after.png` | Sidebar with **zeek disabled** (coverage 4.13%) |

## Capture notes

The committed screenshots are produced by:

```bash
.venv/Scripts/python.exe scripts/run_browser_smoke_test.py
```

That script walks every view, writes the canonical filenames above, and
restores `config.yaml` afterwards (the toggle test rewrites it).

- **Use a tall viewport (1600×2600) for views 2 and 3.** Streamlit scrolls
  inside its own container, so Playwright's `full_page=True` stops at the fold
  and the Recommended Next Sources panel / expanded query fall outside the shot.
- **Expanders must be toggled via the DOM** (`details.open = true`), not a
  synthetic click on `<summary>` — a click is reverted by the next rerun.
- **`data/attack_mappings.csv` resolves from the repository root**, not the
  process CWD (`src.parser.mappings_io.DEFAULT_MAPPINGS_PATH`). Launching from
  an unrelated directory used to raise `FileNotFoundError` on Gap Analysis;
  `tests/test_repo_relative_paths.py` guards it.
- Restore **zeek to enabled** after capturing, so the committed `config.yaml`
  keeps its original contents.

## File Naming
Save to `docs/screenshots/` with exact filenames above.