"""Correlation: group findings that share an entity into ranked leads."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import timedelta
from itertools import pairwise

from huntagent.hunts.base import severity_for
from huntagent.models import TACTIC_ORDER, Finding, Lead, Thresholds

MAX_LINK_USERS = 3
MAX_LINK_HOSTS = 10
MAX_LINK_IPS = 5
MULTI_TACTIC_BONUS = 5
MAX_BONUS = 15

PIVOTS: dict[str, str] = {
    "beaconing": "Find the process that owns the connections and look up the destination in threat intelligence. Isolate the host if the destination is malicious.",
    "dns_tunnel": "Review the queried names for encoded data and block the domain at the resolver. Identify the process making the queries.",
    "dga": "Identify the process generating the lookups and scan the host for the malware family. Check whether any generated name resolved.",
    "exfiltration": "Identify what data left, who owned the session, and whether the destination is sanctioned. Preserve flow records before they roll over.",
    "password_attacks": "Check whether any account signed in successfully from the source, force a reset for those accounts, and block the address.",
    "impossible_travel": "Ask the user, review session activity after the second sign-in, and revoke tokens if the travel is not explained.",
    "lateral_fanout": "Confirm with the administrator whether the activity was planned, then review what ran on each target host.",
    "process_chains": "Collect the full process tree and the file that started it. Detonate the file in a sandbox and hunt for the same hash elsewhere.",
    "persistence": "Inspect the created task, key or service, and remove it once evidence has been preserved.",
    "rare_process": "Hash the binary, check its signature and origin, and search for it on other hosts.",
    "cloud_abuse": "Review the caller's other API activity, rotate its credentials, and confirm that audit logging is still on.",
}


class _UnionFind:
    def __init__(self, size: int) -> None:
        self.parent = list(range(size))

    def find(self, item: int) -> int:
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, a: int, b: int) -> None:
        self.parent[self.find(a)] = self.find(b)


def linkable_entities(finding: Finding) -> set[str]:
    """Entities a finding may be linked through.

    A finding that names many users or addresses (a password spray, for example) is describing a
    campaign, not one victim, so it does not link on those lists.
    """
    entities = {f"domain:{d}" for d in finding.domains}
    if len(finding.hosts) <= MAX_LINK_HOSTS:
        entities |= {f"host:{h}" for h in finding.hosts}
    if len(finding.users) <= MAX_LINK_USERS:
        entities |= {f"user:{u}" for u in finding.users}
    if len(finding.ips) <= MAX_LINK_IPS:
        entities |= {f"ip:{i}" for i in finding.ips}
    return entities


def build_leads(findings: list[Finding], thresholds: Thresholds) -> list[Lead]:
    """Link findings that share an entity and overlap within the lead window, then rank the groups."""
    ordered = sorted(findings, key=lambda f: (f.first_seen, f.id))
    window = timedelta(hours=thresholds.lead_window_hours)
    by_entity: dict[str, list[int]] = defaultdict(list)
    for index, finding in enumerate(ordered):
        for entity in linkable_entities(finding):
            by_entity[entity].append(index)
    groups = _UnionFind(len(ordered))
    for indexes in by_entity.values():
        for a, b in pairwise(indexes):
            if ordered[b].first_seen - ordered[a].last_seen <= window:
                groups.union(a, b)

    buckets: dict[int, list[Finding]] = defaultdict(list)
    for index, finding in enumerate(ordered):
        buckets[groups.find(index)].append(finding)

    leads: list[Lead] = []
    for members in buckets.values():
        top = max(members, key=lambda f: (f.score, f.id))
        tactics = sorted({f.tactic for f in members}, key=lambda t: TACTIC_ORDER.get(t, 99))
        bonus = min(MAX_BONUS, MULTI_TACTIC_BONUS * (len(tactics) - 1))
        score = min(100, top.score + bonus)
        hunts = sorted(
            {f.hunt for f in members}, key=lambda h: -max(f.score for f in members if f.hunt == h)
        )
        title = top.title + (
            f" (and {len(members) - 1} related finding{'s' if len(members) > 2 else ''})"
            if len(members) > 1
            else ""
        )
        leads.append(
            Lead(
                id="L-"
                + hashlib.sha256("|".join(sorted(f.id for f in members)).encode())
                .hexdigest()[:8]
                .upper(),
                score=score,
                severity=severity_for(score),
                title=title,
                tactics=tactics,
                hosts=sorted({h for f in members for h in f.hosts}),
                users=sorted({u for f in members for u in f.users}),
                ips=sorted({i for f in members for i in f.ips}),
                domains=sorted({d for f in members for d in f.domains}),
                first_seen=min(f.first_seen for f in members),
                last_seen=max(f.last_seen for f in members),
                finding_ids=[f.id for f in sorted(members, key=lambda f: (-f.score, f.id))],
                ioc_match=any(f.ioc_match for f in members),
                next_steps=[PIVOTS[h] for h in hunts if h in PIVOTS],
            )
        )
    return sorted(leads, key=lambda lead: (-lead.score, lead.id))
