"""Runnable Phase 2 demo for the ATT&CK Coverage Mapper.

Parses the two anchor sample logs -- data/sample_logs/sample.evtx.xml
(source_format "evtx") and data/sample_logs/sample.aws.json (source_format
"aws_cloudtrail") -- with parser.siem_parsers.parse_log_content(), maps every
resulting LogEvent through parser.attack_mapper.map_events() using the curated
data/attack_mappings.csv ruleset and config.yaml settings, then prints a
per-event mapping report: matched ATT&CK techniques, tactics, confidence
versus detection_confidence_threshold, and datasource type.

Run from the repository root (any CWD works; paths resolve from this file):

    ./.venv/Scripts/python.exe scripts/run_phase2_demo.py

Loader/parser/engine errors (FileNotFoundError, ValueError, ...) propagate
untouched so the demo never masks a broken pipeline. Exit code is 0 on
success.
"""

import logging
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

_SRC_DIR = REPO_ROOT / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from config_loader import load_config  # noqa: E402
from parser.attack_mapper import map_events  # noqa: E402
from parser.log_event_bridge import LogEvent  # noqa: E402
from parser.mappings_io import load_mappings  # noqa: E402
from parser.siem_parsers import parse_log_content  # noqa: E402

logger = logging.getLogger(__name__)

CONFIG_PATH = REPO_ROOT / "config.yaml"
MAPPINGS_PATH = REPO_ROOT / "data" / "attack_mappings.csv"

#: (display title, source_format, sample-log path) for each demo anchor.
ANCHORS: tuple[tuple[str, str, Path], ...] = (
    ("Anchor 1: EVTX Windows Security events", "evtx",
     REPO_ROOT / "data" / "sample_logs" / "sample.evtx.xml"),
    ("Anchor 2: AWS CloudTrail records", "aws_cloudtrail",
     REPO_ROOT / "data" / "sample_logs" / "sample.aws.json"),
)


def parse_anchor(fmt: str, log_path: Path) -> list[LogEvent]:
    """Read *log_path* as UTF-8 text and parse it into LogEvents as *fmt*."""
    content = log_path.read_text(encoding="utf-8")
    return parse_log_content(content, fmt)


def format_event(event: LogEvent, threshold: float) -> list[str]:
    """Format one mapped LogEvent as an indented block of report lines."""
    lines = [
        f"  event {event.event_id[:8]}  action={event.event_action or '-'}"
        f"  time={event.timestamp or '-'}",
        f"    datasource={event.datasource_type or '-'}",
    ]
    if not event.attack_technique_ids:
        lines.append("    techniques=(none matched)")
        return lines
    conf = event.detection_confidence
    marker = "detectable" if conf >= threshold else "below-threshold"
    lines.append(f"    techniques={', '.join(event.attack_technique_ids)}"
                 f"  tactics={', '.join(event.attack_tactics)}")
    lines.append(f"    confidence={conf:.2f}  [{marker} vs threshold {threshold:.2f}]")
    return lines


def summarize(events: list[LogEvent], threshold: float) -> str:
    """Tally one anchor: total events / mapped / distinct detectable techniques.

    A technique counts as detectable when it appears on an event whose
    detection_confidence meets *threshold*.
    """
    mapped = [e for e in events if e.attack_technique_ids]
    detectable = {
        technique
        for event in mapped if event.detection_confidence >= threshold
        for technique in event.attack_technique_ids
    }
    return (f"  {len(events)} events | {len(mapped)} mapped | "
            f"{len(detectable)} distinct techniques >= threshold")


def run_demo(config_path: Path = CONFIG_PATH,
             mappings_path: Path = MAPPINGS_PATH) -> None:
    """Load config + mappings, then print the mapping report for both anchors."""
    config = load_config(str(config_path))
    rules = load_mappings(str(mappings_path))
    threshold = float(config["detection_confidence_threshold"])
    enabled_sources = config["enabled_log_sources"]

    logger.info("demo start: %d rules, threshold %.2f", len(rules), threshold)
    print("ATT&CK Coverage Mapper - Phase 2 mapping demo")
    print(f"  rules loaded : {len(rules)} "
          f"({sum(1 for rule in rules if rule.is_core)} core)")
    print(f"  platform     : {config['platform_scope']}")
    print(f"  threshold    : {threshold:.2f}")
    sources = ", ".join(f"{fmt}={str(on).lower()}"
                        for fmt, on in sorted(enabled_sources.items()))
    print(f"  sources      : {sources}")
    print()

    for title, fmt, path in ANCHORS:
        print(title)
        if enabled_sources.get(fmt) is False:
            # Mirror the engine contract: disabled source => no annotations.
            print(f"  (note: '{fmt}' is disabled in config.yaml; "
                  "the engine suppresses technique annotations)")
        events = map_events(parse_anchor(fmt, path), rules, config)
        for event in events:
            for line in format_event(event, threshold):
                print(line)
        print(summarize(events, threshold))
        print()
    logger.info("demo finished")


def main() -> int:
    """Entry point: configure logging, run the demo, return the exit status."""
    logging.basicConfig(level=logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")
    run_demo()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
