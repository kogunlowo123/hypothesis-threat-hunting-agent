"""Cloud hunts: risky management API activity."""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Any

from huntagent.hunts.base import Hunt, HuntContext, make_finding
from huntagent.models import Event, Finding, Thresholds

PRIVILEGE_APIS = frozenset(
    {
        "CreateAccessKey",
        "CreateUser",
        "AttachUserPolicy",
        "AttachRolePolicy",
        "PutUserPolicy",
        "PutRolePolicy",
        "UpdateAssumeRolePolicy",
        "CreateLoginProfile",
        "AddUserToGroup",
    }
)
EVASION_APIS = frozenset(
    {
        "StopLogging",
        "DeleteTrail",
        "UpdateTrail",
        "PutEventSelectors",
        "DeleteFlowLogs",
        "DisableGuardDuty",
        "DeleteDetector",
    }
)
DISCOVERY_PREFIXES = ("List", "Describe", "Get")


class CloudAbuseHunt(Hunt):
    id = "cloud_abuse"
    name = "Risky cloud management activity"
    tactic = "Persistence"
    techniques = ("T1078.004", "T1098", "T1562.008", "T1526")
    required = ("cloud",)
    description = (
        "Root account use, privilege changes without multi-factor authentication, attempts to switch off "
        "logging, and bursts of enumeration calls from an address the account has not used before."
    )

    def run(self, ctx: HuntContext) -> list[Finding]:
        events = [e for e in ctx.by_kind("cloud") if e.user not in ctx.config.noisy_users]
        return (
            self._root(ctx, events)
            + self._privilege(ctx, events)
            + self._evasion(ctx, events)
            + self._enumeration(ctx, events)
        )

    def _root(self, ctx: HuntContext, events: list[Event]) -> list[Finding]:
        used = [e for e in events if e.user == "root" and e.outcome == "success"]
        if not used:
            return []
        return [
            make_finding(
                self.id,
                f"Root account used {len(used)} time(s)",
                used,
                score=70,
                tactic="Initial Access",
                techniques=["T1078.004"],
                explanation="The root account can do anything and should be reserved for a few account-level tasks.",
                config=ctx.config,
                users=["root"],
                ips=[e.src_ip for e in used],
                details={
                    "calls": sorted({e.api for e in used}),
                    "without_mfa": sum(1 for e in used if e.mfa is False),
                },
                benign=["a planned break-glass action"],
            )
        ]

    def _privilege(self, ctx: HuntContext, events: list[Event]) -> list[Finding]:
        grouped: dict[str, list[Event]] = defaultdict(list)
        for e in events:
            if e.api in PRIVILEGE_APIS and e.outcome == "success" and e.mfa is False:
                grouped[e.user].append(e)
        return [
            make_finding(
                self.id,
                f"{user} changed permissions or credentials without MFA",
                evs,
                score=65 + min(10, 3 * (len(evs) - 1)),
                tactic="Persistence",
                techniques=["T1098", "T1136.003"],
                explanation=f"{len(evs)} sensitive call(s) ({', '.join(sorted({e.api for e in evs}))}) made in a session without multi-factor authentication.",
                config=ctx.config,
                users=[user],
                ips=[e.src_ip for e in evs],
                details={"apis": sorted({e.api for e in evs})},
                benign=["automation using long-lived keys that should be replaced by roles"],
            )
            for user, evs in sorted(grouped.items())
        ]

    def _evasion(self, ctx: HuntContext, events: list[Event]) -> list[Finding]:
        grouped: dict[str, list[Event]] = defaultdict(list)
        for e in events:
            if e.api in EVASION_APIS:
                grouped[e.user].append(e)
        return [
            make_finding(
                self.id,
                f"{user} tried to weaken cloud logging or detection",
                evs,
                score=85,
                tactic="Defense Evasion",
                techniques=["T1562.008"],
                explanation=f"Calls that disable or change audit trails: {', '.join(sorted({e.api for e in evs}))}.",
                config=ctx.config,
                users=[user],
                ips=[e.src_ip for e in evs],
                details={"apis": sorted({e.api for e in evs})},
                benign=["a reviewed migration of logging configuration"],
            )
            for user, evs in sorted(grouped.items())
        ]

    def _enumeration(self, ctx: HuntContext, events: list[Event]) -> list[Finding]:
        t = ctx.thresholds
        window = timedelta(minutes=t.enumeration_window_minutes)
        grouped: dict[tuple[str, str], list[Event]] = defaultdict(list)
        for e in events:
            if e.api.startswith(DISCOVERY_PREFIXES) and e.src_ip:
                grouped[(e.user, e.src_ip)].append(e)
        findings: list[Finding] = []
        for (user, ip), evs in sorted(grouped.items()):
            best: list[Event] = []
            start = 0
            for end in range(len(evs)):
                while evs[end].time - evs[start].time > window:
                    start += 1
                current = evs[start : end + 1]
                if len({e.api for e in current}) > len({e.api for e in best}):
                    best = list(current)
            apis = sorted({e.api for e in best})
            if len(apis) < t.enumeration_min_apis:
                continue
            new_ip = ip not in ctx.baseline.cloud_ips.get(user, set())
            findings.append(
                make_finding(
                    self.id,
                    f"{user} enumerated the environment from {ip}",
                    best,
                    score=50 + (15 if new_ip else 0) + min(10, len(apis) - t.enumeration_min_apis),
                    tactic="Discovery",
                    techniques=["T1526", "T1580"],
                    explanation=f"{len(apis)} different List, Describe or Get calls within {t.enumeration_window_minutes} minutes"
                    + (", from an address this account has not used before." if new_ip else "."),
                    config=ctx.config,
                    users=[user],
                    ips=[ip],
                    details={"distinct_apis": len(apis), "new_source_address": new_ip},
                    benign=[
                        "an inventory or compliance scanner",
                        "an engineer exploring a new account",
                    ],
                )
            )
        return findings

    def spl(self, t: Thresholds) -> str:
        return (
            "index=cloudtrail (eventName=StopLogging OR eventName=DeleteTrail OR eventName=PutEventSelectors OR userIdentity.type=Root)\n"
            "| table _time userIdentity.userName eventName sourceIPAddress"
        )

    def kql(self, t: Thresholds) -> str:
        return 'AWSCloudTrail\n| where EventName in ("StopLogging", "DeleteTrail", "PutEventSelectors") or UserIdentityType == "Root"\n| project TimeGenerated, UserIdentityUserName, EventName, SourceIpAddress'

    def sigma(self, t: Thresholds) -> list[dict[str, Any]]:
        return [
            {
                "title": "Cloud audit logging disabled or changed",
                "id": "cloud_logging_tamper",
                "status": "experimental",
                "description": "Generated from a hunt. Calls that stop or alter audit trails.",
                "logsource": {"product": "aws", "service": "cloudtrail"},
                "detection": {
                    "selection": {"eventName": sorted(EVASION_APIS)},
                    "condition": "selection",
                },
                "falsepositives": ["a reviewed migration of logging configuration"],
                "level": "high",
                "tags": ["attack.defense_evasion", "attack.t1562.008"],
            },
            {
                "title": "Sensitive IAM change without MFA",
                "id": "iam_change_no_mfa",
                "status": "experimental",
                "description": "Generated from a hunt. Permission or credential changes in a session without MFA.",
                "logsource": {"product": "aws", "service": "cloudtrail"},
                "detection": {
                    "selection": {
                        "eventName": sorted(PRIVILEGE_APIS),
                        "additionalEventData.MFAUsed": "No",
                    },
                    "condition": "selection",
                },
                "falsepositives": ["automation using long-lived keys"],
                "level": "high",
                "tags": ["attack.persistence", "attack.t1098"],
            },
        ]
