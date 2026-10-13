"""log_event_bridge.py -- Universal normalized log event schema (vendored).

Adapted locally for the ATT&CK Coverage Mapper from ``schema.py`` of
github.com/TanayBhatt26/siem-log-parser (authored by TanayBhatt26;
owner-authored upstream published without a license file). The upstream
geo/IP-enrichment fields were dropped and replaced by ATT&CK technique /
tactic annotation fields populated post-construction by the mapping engine.

All SIEM-format parsers (see parser.siem_parsers) emit LogEvent instances;
the attack mapper (parser.attack_mapper) annotates them in place.
"""

import logging
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class LogEvent:
    """Normalized representation of a single log event.

    Core fields mirror the upstream siem-log-parser normalization schema so
    the adapted parsers keep identical behavior. The ATT&CK enrichment
    attributes (``attack_technique_ids``, ``attack_tactics``,
    ``datasource_type``, ``detection_confidence``) exist with neutral
    defaults and are set after construction by the mapping engine.
    """

    # --- core identification ---
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: Optional[str] = None
    source_format: str = "unknown"

    # --- network endpoints ---
    source_host: Optional[str] = None
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None

    # --- event semantics ---
    event_type: Optional[str] = None
    event_action: Optional[str] = None
    severity: Optional[str] = None
    severity_code: Optional[int] = None
    category: Optional[str] = None

    # --- actors and processes ---
    username: Optional[str] = None
    user_id: Optional[str] = None
    process_name: Optional[str] = None
    process_id: Optional[int] = None

    # --- traffic details ---
    protocol: Optional[str] = None
    bytes_in: Optional[int] = None
    bytes_out: Optional[int] = None

    # --- payload ---
    message: Optional[str] = None
    raw: Optional[str] = None

    # --- format-specific extras (keys preserved verbatim) ---
    extensions: Dict[str, Any] = field(default_factory=dict)

    # --- ATT&CK enrichment (populated post-init by parser.attack_mapper) ---
    attack_technique_ids: List[str] = field(default_factory=list)
    attack_tactics: List[str] = field(default_factory=list)
    datasource_type: Optional[str] = None
    detection_confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Return the event as a plain dict suitable for JSON export."""
        return asdict(self)


def normalize_severity(value: Any) -> "tuple[str, int]":
    """Normalize a raw severity value to a ``(label, numeric_code)`` pair.

    Accepts ArcSight/CEF codes 0-10, common keyword labels (low, medium,
    high, critical, info, warning, error, alert, emergency, notice, debug)
    case-insensitively; unrecognized values fall back to ``("medium", 5)``.
    Behavior is identical to the upstream siem-log-parser helper.
    """
    mapping = {
        "0": ("low", 1), "1": ("low", 2), "2": ("low", 3),
        "3": ("medium", 4), "4": ("medium", 5), "5": ("medium", 6),
        "6": ("high", 7), "7": ("high", 8),
        "8": ("critical", 9), "9": ("critical", 10), "10": ("critical", 10),
        "low": ("low", 2), "medium": ("medium", 5),
        "high": ("high", 7), "critical": ("critical", 10),
        "info": ("low", 1), "warning": ("medium", 5),
        "error": ("high", 7), "alert": ("critical", 9),
        "emergency": ("critical", 10), "notice": ("low", 2), "debug": ("low", 1),
    }
    return mapping.get(str(value).lower().strip(), ("medium", 5))
