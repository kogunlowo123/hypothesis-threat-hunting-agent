"""Shared machinery for hunts: context, finding construction and the hunt interface."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from huntagent.baseline import Baseline
from huntagent.config import HuntConfig
from huntagent.models import Event, EventKind, Finding, Severity, Thresholds

MAX_EVIDENCE = 50

_SECOND_LEVEL = frozenset(
    {
        "co.uk",
        "org.uk",
        "ac.uk",
        "com.au",
        "net.au",
        "co.jp",
        "co.nz",
        "com.br",
        "co.in",
        "co.za",
        "com.cn",
        "com.mx",
    }
)


@dataclass
class HuntContext:
    """Events in the hunt window plus everything needed to judge them."""

    events: list[Event]
    baseline: Baseline
    config: HuntConfig
    _by_kind: dict[str, list[Event]] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        grouped: dict[str, list[Event]] = defaultdict(list)
        for event in sorted(self.events, key=lambda e: (e.time, e.id)):
            grouped[event.kind].append(event)
        self._by_kind = dict(grouped)

    @property
    def thresholds(self) -> Thresholds:
        return self.config.thresholds

    def by_kind(self, kind: EventKind) -> list[Event]:
        """Events of one kind in time order."""
        return self._by_kind.get(kind, [])


def severity_for(score: int) -> Severity:
    if score >= 85:
        return Severity.CRITICAL
    if score >= 70:
        return Severity.HIGH
    if score >= 45:
        return Severity.MEDIUM
    return Severity.LOW


def registered_domain(domain: str) -> str:
    """The registrable part of a DNS name (``a.b.example.com`` becomes ``example.com``)."""
    labels = domain.lower().rstrip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_off_hours(moment: datetime, start: int, end: int) -> bool:
    """True when ``moment`` falls between ``start`` and ``end`` o'clock (the window may wrap midnight)."""
    hour = moment.hour
    return hour >= start or hour < end if start > end else start <= hour < end


def make_finding(
    hunt: str,
    title: str,
    events: Iterable[Event],
    *,
    score: int,
    tactic: str,
    techniques: list[str],
    explanation: str,
    config: HuntConfig,
    hosts: Iterable[str] = (),
    users: Iterable[str] = (),
    ips: Iterable[str] = (),
    domains: Iterable[str] = (),
    details: dict[str, Any] | None = None,
    benign: list[str] | None = None,
) -> Finding:
    """Build a finding from its evidence events. The score is clamped and IOC matches add a bonus."""
    ordered = sorted(events, key=lambda e: (e.time, e.id))
    host_list = sorted({h for h in hosts if h})
    user_list = sorted({u for u in users if u})
    ip_list = sorted({i for i in ips if i})
    domain_list = sorted({d for d in domains if d})
    ioc = (
        any(i in config.ioc_ips for i in ip_list)
        or any(
            d in config.ioc_domains or registered_domain(d) in config.ioc_domains
            for d in domain_list
        )
        or any(
            e.attrs.get("sha256", "").lower().removeprefix("sha256=") in config.ioc_hashes
            for e in ordered
        )
    )
    final = max(0, min(100, score + (15 if ioc else 0)))
    key = "|".join(
        [hunt, title, *host_list, *user_list, *ip_list, *domain_list, ordered[0].time.isoformat()]
    )
    return Finding(
        id="F-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:10].upper(),
        hunt=hunt,
        title=title,
        score=final,
        severity=severity_for(final),
        tactic=tactic,
        techniques=techniques,
        hosts=host_list,
        users=user_list,
        ips=ip_list,
        domains=domain_list,
        first_seen=ordered[0].time,
        last_seen=ordered[-1].time,
        event_ids=[e.id for e in ordered[:MAX_EVIDENCE]],
        details=details or {},
        explanation=explanation,
        benign_causes=benign or [],
        ioc_match=ioc,
    )


class Hunt:
    """One hypothesis. Subclasses set the class attributes and implement :meth:`run`."""

    id: str = ""
    name: str = ""
    tactic: str = ""
    techniques: tuple[str, ...] = ()
    required: tuple[EventKind, ...] = ()
    description: str = ""

    def unavailable(self, ctx: HuntContext) -> str:
        """A reason this hunt cannot run with the supplied data and configuration, or an empty string."""
        return ""

    def run(self, ctx: HuntContext) -> list[Finding]:
        raise NotImplementedError

    def spl(self, t: Thresholds) -> str:
        """Splunk search that reproduces the hunt's core logic."""
        raise NotImplementedError

    def kql(self, t: Thresholds) -> str:
        """Kusto (Sentinel, Defender) query that reproduces the hunt's core logic."""
        raise NotImplementedError

    def sigma(self, t: Thresholds) -> list[dict[str, Any]]:
        """Sigma rules for pattern-based hunts. Statistical hunts return an empty list."""
        return []
