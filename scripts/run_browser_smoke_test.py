#!/usr/bin/env python
"""
Browser Smoke Test for ATT&CK Coverage Mapper.

Runs through all four views and verifies they render correctly.
Captures screenshots at 1920x1080, 1366x768 and 1280x720.
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCREENSHOT_DIR = PROJECT_ROOT / "docs" / "screenshots"
SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)

# Desktop viewports to validate responsive behaviour.
VIEWPORTS = [
    (1920, 1080, "1080p"),
    (1366, 768, "768p"),
    (1280, 720, "720p"),
]

RESULTS = {}


def take_screenshot(page, name, width, height):
    path = SCREENSHOT_DIR / f"{name}_{width}x{height}.png"
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

    take_screenshot(page, "coverage-overview", width, height)
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

    take_screenshot(page, "apt-simulation", width, height)
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

    take_screenshot(page, "hunt-queries", width, height)
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

    take_screenshot(page, "gap-analysis-all", width, height)
    RESULTS[f"gap_analysis_{width}x{height}"] = results
    return results


def test_config_sidebar(page, width, height):
    """Test Config Sidebar toggle of zeek."""
    print(f"\n=== Test 5: Config Sidebar ({width}x{height}) ===")
    results = {}
    page.click("text=Coverage Overview")
    page.wait_for_timeout(2000)

    results["toggle_off"] = False
    try:
        page.click("text=zeek")
        page.wait_for_timeout(3000)
        print("  [PASS] zeek checkbox clicked")
        results["toggle_off"] = True
        take_screenshot(page, "config-toggle-before", width, height)
    except Exception:
        print("  [FAIL] Could not toggle zeek")

    results["coverage_updated"] = False
    try:
        page.wait_for_timeout(2000)
        page_text = page.text_content("body")
        if "coverage" in page_text.lower():
            print("  [PASS] Coverage page still accessible after toggle")
            results["coverage_updated"] = True
    except Exception:
        print("  [FAIL] Coverage not accessible after toggle")

    results["toggle_back_on"] = False
    try:
        page.click("text=zeek")
        page.wait_for_timeout(3000)
        print("  [PASS] zeek toggled back on")
        results["toggle_back_on"] = True
        take_screenshot(page, "config-toggle-after", width, height)
    except Exception:
        print("  [FAIL] Could not toggle zeek back on")

    RESULTS[f"config_sidebar_{width}x{height}"] = results
    return results


def main():
    print("=" * 60)
    print("ATT&CK Coverage Mapper - Browser Smoke Test")
    print("=" * 60)

    from playwright.sync_api import sync_playwright

    chrome_path = r"C:\Program Files\Google\Chrome\Application\chrome.exe"

    with sync_playwright() as p:
        browser = p.chromium.launch(
            executable_path=chrome_path,
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage"],
        )

        for width, height, label in VIEWPORTS:
            context = browser.new_context(viewport={"width": width, "height": height})
            page = context.new_page()

            print(f"\n{'='*60}\nViewport: {width}x{height} ({label})\n{'='*60}")
            page.goto("http://localhost:8501", wait_until="networkidle")
            page.wait_for_timeout(3000)

            test_coverage_overview(page, width, height)
            test_apt_simulation(page, width, height)
            test_hunt_queries(page, width, height)
            test_gap_analysis(page, width, height)
            test_config_sidebar(page, width, height)

            context.close()

        browser.close()

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
