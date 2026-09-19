"""Domain models: events, findings, leads, thresholds and reports."""

from __future__ import annotations

from datetime import date, datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

EventKind = Literal["process", "auth", "dns", "flow", "cloud"]
SourceFormat = Literal["sysmon", "auth", "dns", "flow", "cloudtrail", "generic"]

TACTIC_ORDER: dict[str, int] = {
    "Initial Access": 1,
    "Execution": 2,
    "Persistence": 3,
    "Privilege Escalation": 4,
    "Defense Evasion": 5,
    "Credential Access": 6,
    "Discovery": 7,
    "Lateral Movement": 8,
    "Collection": 9,
    "Command and Control": 10,
    "Exfiltration": 11,
    "Impact": 12,
}


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return ["low", "medium", "high", "critical"].index(self.value)


class Event(BaseModel):
    """One normalized telemetry record."""

    model_config = ConfigDict(extra="forbid")

    id: str
    time: datetime
    kind: EventKind
    source: str = ""
    host: str = ""
    user: str = ""
    process: str = ""
    parent: str = ""
    cmdline: str = ""
    outcome: Literal["success", "failure", ""] = ""
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    bytes_out: int | None = Field(default=None, ge=0)
    domain: str = ""
    query_type: str = ""
    api: str = ""
    mfa: bool | None = None
    attrs: dict[str, str] = Field(default_factory=dict)

    @field_validator("time")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        return (
            value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
        )

    def describe(self) -> str:
        """One line describing the event, for reports."""
        if self.kind == "process":
            return f"{self.image} {self.cmdline}".strip()[:200]
        if self.kind == "flow":
            size = f" {self.bytes_out} bytes" if self.bytes_out is not None else ""
            return f"connect {self.dst_ip}:{self.dst_port}{size}"
        if self.kind == "dns":
            return f"query {self.domain} {self.query_type} {'NXDOMAIN' if self.outcome == 'failure' else ''}".strip()
        if self.kind == "auth":
            return f"sign-in {self.outcome} from {self.src_ip or 'unknown'} logon {self.attrs.get('logon_type', '')}".strip()
        return f"{self.api} {self.outcome} from {self.src_ip or 'unknown'} mfa={self.mfa}"

    @property
    def image(self) -> str:
        """Lowercase executable name without its directory."""
        return self.process.replace("\\", "/").rsplit("/", 1)[-1].lower()


class Thresholds(BaseModel):
    """Tunable hunt parameters. Every default is a starting point to adjust for the environment."""

    model_config = ConfigDict(extra="forbid")

    beacon_min_connections: int = Field(default=12, ge=3)
    beacon_max_jitter: float = Field(default=0.2, gt=0)
    beacon_min_interval_seconds: int = Field(default=20, ge=1)
    dns_min_subdomains: int = Field(default=25, ge=2)
    dns_min_entropy: float = Field(default=3.4, gt=0)
    dns_min_label_length: int = Field(default=18, ge=4)
    dga_min_nxdomain: int = Field(default=15, ge=2)
    spray_min_users: int = Field(default=8, ge=2)
    spray_window_minutes: int = Field(default=30, ge=1)
    spray_max_attempts_per_user: int = Field(default=3, ge=1)
    bruteforce_min_failures: int = Field(default=10, ge=3)
    travel_window_hours: float = Field(default=3.0, gt=0)
    fanout_min_hosts: int = Field(default=5, ge=2)
    fanout_window_minutes: int = Field(default=30, ge=1)
    exfil_min_bytes: int = Field(default=50_000_000, ge=1)
    exfil_min_zscore: float = Field(default=3.0, gt=0)
    rare_max_hosts: int = Field(default=2, ge=1)
    enumeration_min_apis: int = Field(default=6, ge=2)
    enumeration_window_minutes: int = Field(default=10, ge=1)
    off_hours_start: int = Field(default=22, ge=0, le=23)
    off_hours_end: int = Field(default=6, ge=0, le=23)
    lead_window_hours: int = Field(default=24, ge=1)


class Finding(BaseModel):
    """A hunt's result for one entity."""

    id: str
    hunt: str
    title: str
    score: int = Field(ge=0, le=100)
    severity: Severity
    tactic: str
    techniques: list[str]
    hosts: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
    event_ids: list[str]
    details: dict[str, Any] = Field(default_factory=dict)
    explanation: str
    benign_causes: list[str] = Field(default_factory=list)
    ioc_match: bool = False

    def entities(self) -> set[str]:
        return (
            {f"host:{h}" for h in self.hosts}
            | {f"user:{u}" for u in self.users}
            | {f"ip:{i}" for i in self.ips}
            | {f"domain:{d}" for d in self.domains}
        )


class Suppression(BaseModel):
    """A reviewed, time-limited decision to ignore a known-benign finding."""

    model_config = ConfigDict(extra="forbid")

    hunt: str
    entity: Literal["host", "user", "ip", "domain"]
    value: str
    reason: str = Field(min_length=10, max_length=300)
    approved_by: str = Field(min_length=1, max_length=100)
    expires: date


class Lead(BaseModel):
    """Findings that share an entity, ranked for an analyst to pursue."""

    id: str
    score: int
    severity: Severity
    title: str
    tactics: list[str]
    hosts: list[str]
    users: list[str]
    ips: list[str]
    domains: list[str]
    first_seen: datetime
    last_seen: datetime
    finding_ids: list[str]
    ioc_match: bool
    next_steps: list[str]


class HuntInfo(BaseModel):
    id: str
    name: str
    tactic: str
    techniques: list[str]
    required: list[str]
    description: str


class CoverageRow(BaseModel):
    hunt: str
    name: str
    tactic: str
    techniques: list[str]
    required: list[str]
    missing: list[str]
    runnable: bool


class Coverage(BaseModel):
    kinds_present: dict[str, int]
    rows: list[CoverageRow]
    blind_techniques: list[str]
    covered_techniques: list[str]


class EvidenceEvent(BaseModel):
    """A short, redacted view of an event that supports a finding."""

    id: str
    time: datetime
    kind: str
    host: str
    user: str
    summary: str


class HuntReport(BaseModel):
    hunt_start: datetime
    hunt_end: datetime
    baseline_start: datetime | None
    events_hunted: int
    events_baseline: int
    kinds: dict[str, int]
    findings: list[Finding]
    leads: list[Lead]
    evidence: list[EvidenceEvent] = Field(default_factory=list)
    suppressed: int
    expired_suppressions: list[Suppression]
    skipped_hunts: list[str]
    warnings: list[str]
    summary: str = ""


class IngestReport(BaseModel):
    source: str
    lines: int = 0
    accepted: int = 0
    rejected: int = 0
    errors: list[str] = Field(default_factory=list)
