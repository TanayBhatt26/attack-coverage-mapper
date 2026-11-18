#!/usr/bin/env python
"""
Browser smoke test + screenshot capture for the ATT&CK Coverage Mapper.

Saves the canonical filenames referenced by README.md and
docs/SCREENSHOT_CAPTURE_GUIDE.md (``coverage-overview.png`` etc.) at
1600x1000, and re-checks rendering at 1366x768 and 1280x720 without
overwriting them.

Start the dashboard first, then run this from the repo root:

    PYTHONPATH=src .venv/Scripts/python.exe -m streamlit run src/visualization/app.py
    .venv/Scripts/python.exe scripts/run_browser_smoke_test.py
"""
import shutil
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCREENSHOT_DIR = PROJECT_ROOT / "docs" / "screenshots"
SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_PATH = PROJECT_ROOT / "config.yaml"
CONFIG_BACKUP = PROJECT_ROOT / "config.yaml.smoketest.bak"

#: Viewport used for the committed screenshots.
CANONICAL = (1600, 1000)
#: Extra viewports checked for responsive behaviour only.
CHECK_ONLY = [(1366, 768), (1280, 720)]

#: Sidebar checkboxes render alphabetically; zeek is the last of eight.
ZEEK_INDEX = 7

CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
BASE_URL = "http://localhost:8501"

RESULTS: dict[str, dict[str, bool]] = {}


def take_screenshot(page, name: str) -> str:
    """Capture the canonical filename (no viewport suffix)."""
    path = SCREENSHOT_DIR / f"{name}.png"
    page.screenshot(path=str(path), full_page=True)
    print(f"  Screenshot saved: {path}")
    return str(path)


def _check(page, label, selector, timeout=5000):
    try:
        page.wait_for_selector(selector, timeout=timeout)
        print(f"  [PASS] {label}")
        return True
    except Exception:
        print(f"  [FAIL] {label} not found")
        return False


def _check_text(page, label, text, timeout=5000):
    try:
        page.wait_for_selector(f"text={text}", timeout=timeout)
        print(f"  [PASS] {label}: {text}")
        return True
    except Exception:
        print(f"  [FAIL] {label}: {text} not found")
        return False


def test_coverage_overview(page, width, height):
    """Test Coverage Overview view."""
    print(f"\n=== Test 1: Coverage Overview ({width}x{height}) ===")
    results = {}
    page.click("text=Coverage Overview")
    page.wait_for_timeout(2000)

    results["page_title"] = _check(page, "Page title", "text=Coverage Overview")
    for kpi_text in ["606", "31", "5.12%", "windows", "0.6"]:
        results[f"kpi_{kpi_text}"] = _check_text(page, f"KPI {kpi_text}", kpi_text)
    results["heatmap"] = _check(page, "Plotly heatmap", ".plotly")

    take_screenshot(page, "coverage-overview")
    RESULTS[f"coverage_overview_{width}x{height}"] = results
    return results


def _select_group(page):
    """Select G0016 (APT29) in the sidebar APT group combobox.

    Streamlit's selectbox is a React Aria ComboBox: an `<input
    role="combobox">` whose dropdown listbox is virtualized (only visible
    options render).  Clicking the input with ``force=True`` opens it, then
    typing "APT29" filters the list so G0016's option becomes visible and
    clickable.  We match on the group's primary name "APT29" rather than
    the group id "G0016".
    """
    input_el = page.locator('[data-testid="stSelectbox"] input[role="combobox"]').first
    input_el.click(force=True)
    page.wait_for_timeout(1500)

    # Type the group's primary name to filter the virtualized listbox.
    input_el.fill("")
    input_el.type("APT29", delay=50)
    page.wait_for_timeout(1500)

    selected = False
    last_err = None
    strategies = [
        lambda: page.get_by_role("option").filter(has_text="APT29").first,
        lambda: page.locator("text=APT29").first,
        lambda: page.locator('[role="listbox"]').locator("text=APT29").first,
    ]
    for strat in strategies:
        try:
            opt = strat()
            opt.wait_for(state="visible", timeout=8000)
            opt.click()
            page.wait_for_timeout(1000)
            selected = True
            break
        except Exception as exc:  # try next strategy
            last_err = exc
            continue
    if not selected:
        raise RuntimeError(f"Could not select APT29/G0016: {last_err}")


def test_apt_simulation(page, width, height):
    """Test APT Simulation: select G0016, run, verify KPIs."""
    print(f"\n=== Test 2: APT Simulation ({width}x{height}) ===")
    results = {}
    page.click("text=APT Simulation")
    page.wait_for_timeout(2000)

    results["page_title"] = _check(page, "Page title", "text=APT Simulation")

    try:
        _select_group(page)
        print("  [PASS] Selected G0016 in group picker")
        results["group_picker"] = True
    except Exception as e:
        print(f"  [FAIL] Could not select G0016: {e}")
        results["group_picker"] = False

    try:
        page.click("text=Run simulation")
        page.wait_for_timeout(5000)
        print("  [PASS] Run simulation clicked")
        results["run_button"] = True
    except Exception:
        print("  [FAIL] Run simulation button not found")
        results["run_button"] = False

    for kpi_text in ["66", "6", "2", "58", "12.12%"]:
        results[f"kpi_{kpi_text}"] = _check_text(page, f"KPI {kpi_text}", kpi_text)

    results["bar_chart"] = _check(page, "Per-tactic bar chart", ".plotly")
    results["recommendations"] = _check(page, "Recommendations", "text=Recommended next sources")
    results["missed_expander"] = _check(page, "Missed techniques expander", "text=Missed techniques")

    take_screenshot(page, "apt-simulation")
    RESULTS[f"apt_simulation_{width}x{height}"] = results
    return results


def test_hunt_queries(page, width, height):
    """Test Hunt Queries (requires simulation run first)."""
    print(f"\n=== Test 3: Hunt Queries ({width}x{height}) ===")
    results = {}
    page.click("text=Hunt Queries")
    page.wait_for_timeout(2000)

    # Hunt Queries needs a simulation result id. The number_input defaults to
    # the most recent result id (the run we just performed), so export_all_queries
    # runs automatically once we wait for it to render.
    page.wait_for_timeout(2000)

    results["page_title"] = _check(page, "Page title", "text=Hunt — missed techniques")

    # The gap list renders as a Streamlit dataframe (div grid, not <table>).
    # The "Gap list (N missed)" subheader only renders when queries exist, so
    # it is a more reliable assertion than matching a virtualized dataframe cell.
    results["gap_table"] = _check_text(page, "Gap list subheader", "Gap list")
    try:
        rows = page.locator("details").count()
        print(f"  [INFO] Technique expanders found: {rows}")
        results["row_count"] = rows >= 1
    except Exception:
        results["row_count"] = False

    results["expander_opens"] = False
    try:
        expanders = page.locator("details")
        count = expanders.count()
        print(f"  [INFO] Expanders found: {count}")
        if count > 0:
            expanders.first.click()
            page.wait_for_timeout(2000)
            results["expander_opens"] = True
            print("  [PASS] First expander opened")
    except Exception as e:
        print(f"  [FAIL] Expander test error: {e}")

    take_screenshot(page, "hunt-queries")
    RESULTS[f"hunt_queries_{width}x{height}"] = results
    return results


def test_gap_analysis(page, width, height):
    """Test Gap Analysis four tabs."""
    print(f"\n=== Test 4: Gap Analysis ({width}x{height}) ===")
    results = {}
    page.click("text=Gap Analysis")
    page.wait_for_timeout(2000)

    results["page_title"] = _check(page, "Page title", "text=Gap Analysis")

    tabs = ["Remediation Bundles", "Tactic Groups", "Exploratory KMeans", "All Gaps"]
    for tab in tabs:
        results[f"tab_{tab.lower().replace(' ', '_')}"] = _check(page, f"Tab {tab}", f"text={tab}", timeout=3000)
        page.wait_for_timeout(1500)

    take_screenshot(page, "gap-analysis-all")
    RESULTS[f"gap_analysis_{width}x{height}"] = results

    # Anomaly Detection (fifth view).
    print(f"\n=== Test 5: Anomaly Detection ({width}x{height}) ===")
    page.click("text=Anomaly Detection")
    page.wait_for_timeout(4000)
    results["anomaly_page_title"] = _check(page, "Page title", "text=Anomaly Detection")
    results["anomaly_rate"] = _check_text(page, "Anomaly rate", "Anomaly rate")
    take_screenshot(page, "anomaly-detection")
    RESULTS[f"anomaly_detection_{width}x{height}"] = results
    return results


def test_config_sidebar(page, width, height):
    """Capture the zeek on/off pair, then restore the checkbox.

    ``config-toggle-before`` is zeek ENABLED (the default) and
    ``config-toggle-after`` is zeek DISABLED.  The previous version captured
    them in the opposite order.
    """
    print(f"\n=== Test 6: Config Sidebar ({width}x{height}) ===")
    results = {}
    page.click("text=Coverage Overview")
    page.wait_for_timeout(2000)

    expander = page.locator('[data-testid="stExpander"]').filter(has_text="Configuration")
    expander.first.locator("summary").click()
    page.wait_for_timeout(3000)

    zeek = page.locator('[data-testid="stCheckbox"]').nth(ZEEK_INDEX)
    before = zeek.locator("label").first.get_attribute("data-selected")
    print(f"  zeek before  : {before}")
    take_screenshot(page, "config-toggle-before")

    try:
        zeek.click()
        page.wait_for_timeout(7000)
        after = zeek.locator("label").first.get_attribute("data-selected")
        print(f"  zeek after   : {after}")
        results["toggle_off"] = after != before
        take_screenshot(page, "config-toggle-after")
    except Exception as exc:
        print(f"  [FAIL] Could not toggle zeek: {exc}")
        results["toggle_off"] = False

    try:
        zeek.click()
        page.wait_for_timeout(7000)
        restored = zeek.locator("label").first.get_attribute("data-selected")
        print(f"  zeek restored: {restored}")
        results["toggle_back_on"] = restored == before
    except Exception as exc:
        print(f"  [FAIL] Could not restore zeek: {exc}")
        results["toggle_back_on"] = False

    RESULTS[f"config_sidebar_{width}x{height}"] = results
    return results


def main():
    print("=" * 60)
    print("ATT&CK Coverage Mapper - Browser Smoke Test")
    print("=" * 60)

    from playwright.sync_api import sync_playwright

    # The config toggle rewrites config.yaml; keep the original and restore it.
    shutil.copyfile(CONFIG_PATH, CONFIG_BACKUP)
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                executable_path=CHROME,
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )

            width, height = CANONICAL
            context = browser.new_context(viewport={"width": width, "height": height})
            page = context.new_page()
            print(f"\n{'='*60}\nCapturing at {width}x{height}\n{'='*60}")
            page.goto(BASE_URL, wait_until="networkidle")
            page.wait_for_timeout(4000)

            test_coverage_overview(page, width, height)
            test_apt_simulation(page, width, height)
            test_hunt_queries(page, width, height)
            test_gap_analysis(page, width, height)
            test_config_sidebar(page, width, height)
            context.close()

            for chk_w, chk_h in CHECK_ONLY:
                print(f"\n{'='*60}\nResponsive check {chk_w}x{chk_h}\n{'='*60}")
                chk = browser.new_context(viewport={"width": chk_w, "height": chk_h})
                chk_page = chk.new_page()
                chk_page.goto(BASE_URL, wait_until="networkidle")
                chk_page.wait_for_timeout(4000)
                RESULTS[f"responsive_{chk_w}x{chk_h}"] = {
                    "renders": _check(chk_page, "KPI row", "text=5.12%", 8000),
                }
                chk.close()

            browser.close()
    finally:
        shutil.copyfile(CONFIG_BACKUP, CONFIG_PATH)
        CONFIG_BACKUP.unlink(missing_ok=True)
        print("\nconfig.yaml restored from backup")

    print("\n" + "=" * 60)
    print("BROWSER SMOKE TEST COMPLETE")
    print("=" * 60)
    print(f"Screenshots saved to: {SCREENSHOT_DIR}")

    total_pass = 0
    total_checks = 0
    for viewport_key, result_dict in RESULTS.items():
        passed = sum(1 for v in result_dict.values() if v is True)
        total = len(result_dict)
        total_pass += passed
        total_checks += total
        print(f"  {viewport_key}: {passed}/{total} checks passed")

    print(f"\nTOTAL: {total_pass}/{total_checks} checks passed")


if __name__ == "__main__":
    main()
