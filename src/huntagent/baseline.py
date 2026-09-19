"""Baseline: what normal looks like, learned from events before the hunt window."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from huntagent.config import HuntConfig
from huntagent.models import Event
from huntagent.security import is_internal_ip


@dataclass
class Baseline:
    """Sets and samples that hunts compare the hunt window against."""

    events: int = 0
    days: int = 0
    process_hosts: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    host_destinations: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    user_hosts: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    user_countries: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    host_daily_out: dict[str, list[float]] = field(default_factory=lambda: defaultdict(list))
    cloud_ips: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    domains: set[str] = field(default_factory=set)

    @property
    def has_processes(self) -> bool:
        return bool(self.process_hosts)

    @property
    def has_traffic(self) -> bool:
        return bool(self.host_destinations)

    @classmethod
    def build(cls, events: list[Event], config: HuntConfig) -> Baseline:
        """Learn from ``events``, which should all predate the hunt window."""
        baseline = cls(events=len(events))
        daily: dict[tuple[str, str], float] = defaultdict(float)
        days: set[str] = set()
        for e in events:
            days.add(e.time.date().isoformat())
            if e.kind == "process" and e.image:
                baseline.process_hosts[e.image].add(e.host)
            elif e.kind == "flow" and e.dst_ip and not is_internal_ip(e.dst_ip):
                baseline.host_destinations[e.host].add(e.dst_ip)
                daily[(e.host, e.time.date().isoformat())] += e.bytes_out or 0
            elif e.kind == "auth" and e.outcome == "success":
                baseline.user_hosts[e.user].add(e.host)
                country = config.country_of(e.src_ip)
                if country:
                    baseline.user_countries[e.user].add(country)
            elif e.kind == "cloud" and e.src_ip:
                baseline.cloud_ips[e.user].add(e.src_ip)
            elif e.kind == "dns" and e.domain:
                baseline.domains.add(e.domain)
        for (host, _), total in sorted(daily.items()):
            baseline.host_daily_out[host].append(total)
        baseline.days = len(days)
        return baseline
