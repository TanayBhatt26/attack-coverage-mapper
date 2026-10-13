"""SQLAlchemy models - ATT&CK Coverage Mapper.

Table names follow blueprint section 11.1; portability rules (plain JSON,
no native enums, lowercase-at-write lookups) apply for SQLite/Postgres parity.
"""
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Technique(Base):
    """ATT&CK Enterprise technique or sub-technique."""

    __tablename__ = "techniques"

    stix_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    attack_id: Mapped[str] = mapped_column(String(16), index=True)  # T1059.001
    name: Mapped[str] = mapped_column(String(256))
    description: Mapped[str | None] = mapped_column(Text)
    tactics: Mapped[list] = mapped_column(JSON, default=list)
    platforms: Mapped[list] = mapped_column(JSON, default=list)
    detection_strategy_refs: Mapped[list] = mapped_column(JSON, default=list)
    is_subtechnique: Mapped[bool] = mapped_column(Boolean, default=False)
    parent_attack_id: Mapped[str | None] = mapped_column(String(16))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class DetectionStrategy(Base):
    """Structured v18+ detection guidance object (DET####)."""

    __tablename__ = "detection_strategies"

    stix_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    det_id: Mapped[str | None] = mapped_column(String(16), index=True)
    name: Mapped[str] = mapped_column(String(256))
    technique_stix_id: Mapped[str | None] = mapped_column(
        ForeignKey("techniques.stix_id"), index=True
    )


class Analytic(Base):
    """Structured v18+ analytic object (AN####) belonging to a strategy."""

    __tablename__ = "analytics"

    stix_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    an_id: Mapped[str | None] = mapped_column(String(16), index=True)
    name: Mapped[str | None] = mapped_column(String(256))
    description: Mapped[str | None] = mapped_column(Text)
    strategy_stix_id: Mapped[str | None] = mapped_column(
        ForeignKey("detection_strategies.stix_id"), index=True
    )
    log_source_refs: Mapped[list] = mapped_column(JSON, default=list)


class AptGroup(Base):
    __tablename__ = "apt_groups"

    # Natural key: STIX ID is stable across bundle refreshes, so merge()
    # upserts work on re-runs. (A surrogate autoincrement PK would break
    # idempotent loads - merge() cannot match unsupplied PKs.)
    stix_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    group_id: Mapped[str] = mapped_column(String(16), index=True)  # G0016
    name: Mapped[str] = mapped_column(String(256))
    aliases: Mapped[list] = mapped_column(JSON, default=list)
    description: Mapped[str | None] = mapped_column(Text)


class AptTechnique(Base):
    """Association: techniques a group is known to use."""

    __tablename__ = "apt_technique"

    group_stix_id: Mapped[str] = mapped_column(
        ForeignKey("apt_groups.stix_id"), primary_key=True
    )
    technique_stix_id: Mapped[str] = mapped_column(
        ForeignKey("techniques.stix_id"), primary_key=True
    )


class DataSourceType(Base):
    """A log format the simulated team may collect (siem-log-parser vocab)."""

    __tablename__ = "datasource_types"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    log_format: Mapped[str] = mapped_column(String(20))
    priority: Mapped[int] = mapped_column(Integer, default=0)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    __table_args__ = (
        CheckConstraint(
            "log_format IN ('syslog','cef','leef','json','evtx',"
            "'aws_cloudtrail','nginx','zeek')",
            name="ck_ds_logformat",
        ),
    )


class TechniqueCoverage(Base):
    """Detectability of one technique given one enabled datasource."""

    __tablename__ = "technique_coverage"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    technique_stix_id: Mapped[str] = mapped_column(
        ForeignKey("techniques.stix_id"), index=True
    )
    technique_attack_id: Mapped[str] = mapped_column(String(16), index=True)
    datasource_id: Mapped[int] = mapped_column(
        ForeignKey("datasource_types.id", ondelete="CASCADE"), index=True
    )
    is_detectable: Mapped[bool] = mapped_column(Boolean, default=False)
    detection_confidence: Mapped[float] = mapped_column(Float, default=0.0)
    required_fields: Mapped[list] = mapped_column(JSON, default=list)
    sigma_rule_id: Mapped[str | None] = mapped_column(String(80))
    splunk_query: Mapped[str | None] = mapped_column(Text)
    eql_query: Mapped[str | None] = mapped_column(Text)
    # Phase 5 hunt-query provenance. query_source is one of:
    #   'sigmahq'        — query derived from a SigmaHQ rule (pySigma convert)
    #   'curated'        — hand-curated core mapping (M001-M020)
    #   'generic_template' — UNREVIEWED fallback template
    # NULL when no hunt query has been generated yet (pre-Phase-5 rows).
    query_source: Mapped[str | None] = mapped_column(String(16))
    # Phase 5 DRL 1.1 attribution blob for community-sourced queries. Empty
    # dict when unused. Populated (only) when query_source == 'sigmahq':
    #   {author, rule_uuid, rule_url, rule_set_url, license, license_url,
    #    attribution_text}  (see detections.hand_written attribution contract).
    attribution_json: Mapped[dict] = mapped_column(JSON, default=dict)

    __table_args__ = (
        UniqueConstraint("technique_stix_id", "datasource_id", name="uq_cov_pair"),
    )


class SimulationResult(Base):
    __tablename__ = "simulation_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_stix_id: Mapped[str] = mapped_column(
        ForeignKey("apt_groups.stix_id"), index=True
    )
    group_id: Mapped[str] = mapped_column(String(16))  # G0016
    run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    platform_scope: Mapped[str] = mapped_column(String(32))
    confidence_threshold: Mapped[float] = mapped_column(Float)
    total_techniques: Mapped[int] = mapped_column(Integer)
    detected_count: Mapped[int] = mapped_column(Integer)
    missed_count: Mapped[int] = mapped_column(Integer)
    coverage_pct: Mapped[float] = mapped_column(Float)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)


class SimulationTechnique(Base):
    __tablename__ = "simulation_techniques"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    result_id: Mapped[int] = mapped_column(
        ForeignKey("simulation_results.id", ondelete="CASCADE"), index=True
    )
    technique_attack_id: Mapped[str] = mapped_column(String(16))
    name: Mapped[str | None] = mapped_column(String(256))
    tactic: Mapped[str | None] = mapped_column(String(48))
    # detected | detected_rollup | missed
    status: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[float | None] = mapped_column(Float)
    contributing_sources: Mapped[list] = mapped_column(JSON, default=list)

    __table_args__ = (
        CheckConstraint(
            "status IN ('detected','detected_rollup','missed')",
            name="ck_sim_status",
        ),
    )


class AttackMeta(Base):
    """Single-row snapshot pinning: which library/bundle produced this DB."""

    __tablename__ = "attack_meta"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    library_version: Mapped[str | None] = mapped_column(String(32))
    bundle_version: Mapped[str | None] = mapped_column(String(32))
    bundle_date: Mapped[str | None] = mapped_column(String(64))
    object_count: Mapped[int] = mapped_column(Integer, default=0)
    loaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
