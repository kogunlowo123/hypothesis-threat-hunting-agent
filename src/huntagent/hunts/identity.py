"""Identity hunts: password attacks, impossible travel and lateral movement fan-out."""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from datetime import timedelta
from itertools import pairwise

from huntagent.hunts.base import Hunt, HuntContext, make_finding
from huntagent.models import Event, Finding, Thresholds

_NETWORK_LOGONS = frozenset({"3", "10", "network", "rdp", "smb", "remoteinteractive"})


def _auth_like(ctx: HuntContext) -> list[Event]:
    """Authentication events, including cloud console logins."""
    events = list(ctx.by_kind("auth")) + [
        e for e in ctx.by_kind("cloud") if e.api == "ConsoleLogin"
    ]
    return sorted(events, key=lambda e: (e.time, e.id))


class PasswordAttackHunt(Hunt):
    id = "password_attacks"
    name = "Password spraying and brute force"
    tactic = "Credential Access"
    techniques = ("T1110.003", "T1110.001")
    required = ("auth",)
    description = (
        "One source failing to sign in as many different accounts (spraying), or many failures against one "
        "account (brute force), especially when a success follows."
    )

    def run(self, ctx: HuntContext) -> list[Finding]:
        return self._spray(ctx) + self._bruteforce(ctx)

    def _spray(self, ctx: HuntContext) -> list[Finding]:
        t = ctx.thresholds
        window = timedelta(minutes=t.spray_window_minutes)
        events = _auth_like(ctx)
        failures: dict[str, list[Event]] = defaultdict(list)
        successes: dict[str, list[Event]] = defaultdict(list)
        for e in events:
            if not e.src_ip or e.src_ip in ctx.config.scanner_ips:
                continue
            (failures if e.outcome == "failure" else successes)[e.src_ip].append(e)
        findings: list[Finding] = []
        for ip, fails in sorted(failures.items()):
            best: list[Event] = []
            start = 0
            for end in range(len(fails)):
                while fails[end].time - fails[start].time > window:
                    start += 1
                current = fails[start : end + 1]
                users = Counter(e.user for e in current)
                if (
                    len(users) >= t.spray_min_users
                    and max(users.values()) <= t.spray_max_attempts_per_user
                    and len(users) > len({e.user for e in best})
                ):
                    best = list(current)
            if not best:
                continue
            accounts = sorted({e.user for e in best})
            wins = [
                s for s in successes.get(ip, []) if s.user in accounts and s.time >= best[0].time
            ]
            score = 55 + min(15, (len(accounts) - t.spray_min_users) * 2) + (25 if wins else 0)
            findings.append(
                make_finding(
                    self.id,
                    f"Password spray from {ip} against {len(accounts)} accounts"
                    + (" with a successful sign-in" if wins else ""),
                    best + wins,
                    score=score,
                    tactic=self.tactic,
                    techniques=["T1110.003"],
                    explanation=(
                        f"{len(best)} failures across {len(accounts)} accounts within {t.spray_window_minutes} minutes, "
                        f"at most {max(Counter(e.user for e in best).values())} attempt(s) per account."
                        + (
                            f" Accounts that later signed in from the same address: {', '.join(sorted({w.user for w in wins}))}."
                            if wins
                            else ""
                        )
                    ),
                    config=ctx.config,
                    users=[e.user for e in best] + [w.user for w in wins],
                    ips=[ip],
                    details={
                        "accounts": len(accounts),
                        "failures": len(best),
                        "successful_accounts": sorted({w.user for w in wins}),
                    },
                    benign=[
                        "a shared office egress address with many users mistyping after a password expiry",
                        "a vulnerability scanner not yet in the allowlist",
                    ],
                )
            )
        return findings

    def _bruteforce(self, ctx: HuntContext) -> list[Finding]:
        t = ctx.thresholds
        window = timedelta(minutes=10)
        per_user: dict[str, list[Event]] = defaultdict(list)
        for e in _auth_like(ctx):
            if (
                e.user
                and e.user not in ctx.config.noisy_users
                and e.src_ip not in ctx.config.scanner_ips
            ):
                per_user[e.user].append(e)
        findings: list[Finding] = []
        for user, events in sorted(per_user.items()):
            fails = [e for e in events if e.outcome == "failure"]
            for i in range(len(fails)):
                burst = [f for f in fails[i:] if f.time - fails[i].time <= window]
                if len(burst) < t.bruteforce_min_failures:
                    continue
                wins = [
                    e
                    for e in events
                    if e.outcome == "success"
                    and burst[-1].time <= e.time <= burst[-1].time + window
                ]
                score = 50 + min(20, len(burst) - t.bruteforce_min_failures) + (25 if wins else 0)
                findings.append(
                    make_finding(
                        self.id,
                        f"{len(burst)} failed sign-ins for {user} in 10 minutes"
                        + (", then a success" if wins else ""),
                        burst + wins,
                        score=score,
                        tactic=self.tactic,
                        techniques=["T1110.001"],
                        explanation=f"{len(burst)} failures for one account within 10 minutes"
                        + (", followed by a successful sign-in." if wins else "."),
                        config=ctx.config,
                        users=[user],
                        ips=[e.src_ip for e in burst + wins],
                        details={"failures": len(burst), "followed_by_success": bool(wins)},
                        benign=[
                            "a user with a stale saved password on a phone",
                            "a service account with an expired secret",
                        ],
                    )
                )
                break
        return findings

    def spl(self, t: Thresholds) -> str:
        return (
            "index=auth result=failure\n| bin _time span=" + f"{t.spray_window_minutes}m\n"
            "| stats dc(user) as accounts count as failures by _time src_ip\n"
            f"| where accounts>={t.spray_min_users} AND failures/accounts<={t.spray_max_attempts_per_user}"
        )

    def kql(self, t: Thresholds) -> str:
        return (
            f"SigninLogs\n| where ResultType != 0\n| summarize Accounts=dcount(UserPrincipalName), Failures=count() by IPAddress, bin(TimeGenerated, {t.spray_window_minutes}m)\n"
            f"| where Accounts >= {t.spray_min_users} and Failures / Accounts <= {t.spray_max_attempts_per_user}"
        )


class ImpossibleTravelHunt(Hunt):
    id = "impossible_travel"
    name = "Impossible travel"
    tactic = "Initial Access"
    techniques = ("T1078",)
    required = ("auth",)
    description = (
        "The same account signing in from two different countries too close together in time."
    )

    def unavailable(self, ctx: HuntContext) -> str:
        return (
            ""
            if ctx.config.geo
            else "no geography file configured, so addresses cannot be placed in countries"
        )

    def run(self, ctx: HuntContext) -> list[Finding]:
        t = ctx.thresholds
        limit = timedelta(hours=t.travel_window_hours)
        per_user: dict[str, list[tuple[Event, str]]] = defaultdict(list)
        for e in _auth_like(ctx):
            if (
                e.outcome != "success"
                or not e.user
                or not e.src_ip
                or ctx.config.is_allowed_destination(ip=e.src_ip)
            ):
                continue
            country = ctx.config.country_of(e.src_ip)
            if country:
                per_user[e.user].append((e, country))
        findings: list[Finding] = []
        for user, seq in sorted(per_user.items()):
            for (a, ca), (b, cb) in pairwise(seq):
                if ca == cb or b.time - a.time > limit:
                    continue
                known = ctx.baseline.user_countries.get(user, set())
                new_country = bool(known) and cb not in known
                gap = (b.time - a.time).total_seconds() / 3600
                score = (
                    55 + (15 if new_country else 0) + int(15 * (1 - gap / t.travel_window_hours))
                )
                findings.append(
                    make_finding(
                        self.id,
                        f"{user} signed in from {ca} and {cb} within {gap:.1f} hours",
                        [a, b],
                        score=score,
                        tactic=self.tactic,
                        techniques=list(self.techniques),
                        explanation=f"Sign-ins from {a.src_ip} ({ca}) and {b.src_ip} ({cb}) are {gap:.1f} hours apart"
                        + (f"; {cb} is new for this account." if new_country else "."),
                        config=ctx.config,
                        users=[user],
                        ips=[a.src_ip, b.src_ip],
                        details={
                            "countries": [ca, cb],
                            "hours_apart": round(gap, 2),
                            "new_country": new_country,
                        },
                        benign=[
                            "a VPN or proxy with exit nodes in several countries",
                            "a mobile carrier routing through another country",
                        ],
                    )
                )
        return findings

    def spl(self, t: Thresholds) -> str:
        return (
            "index=auth result=success\n| iplocation src_ip\n| sort 0 user _time\n| streamstats current=f last(Country) as prev_country last(_time) as prev_time by user\n"
            f"| eval hours=(_time-prev_time)/3600\n| where Country!=prev_country AND hours<={t.travel_window_hours}"
        )

    def kql(self, t: Thresholds) -> str:
        return (
            "SigninLogs\n| where ResultType == 0\n| extend Country = tostring(LocationDetails.countryOrRegion)\n| sort by UserPrincipalName asc, TimeGenerated asc\n"
            f"| extend PrevCountry = prev(Country), PrevTime = prev(TimeGenerated), PrevUser = prev(UserPrincipalName)\n"
            f"| where UserPrincipalName == PrevUser and Country != PrevCountry and (TimeGenerated - PrevTime) <= {t.travel_window_hours}h"
        )


class LateralFanOutHunt(Hunt):
    id = "lateral_fanout"
    name = "Lateral movement fan-out"
    tactic = "Lateral Movement"
    techniques = ("T1021.001", "T1021.002", "T1078")
    required = ("auth",)
    description = "One account signing in over the network or RDP to many hosts it does not normally touch, in a short time."

    def run(self, ctx: HuntContext) -> list[Finding]:
        t = ctx.thresholds
        window = timedelta(minutes=t.fanout_window_minutes)
        groups: dict[tuple[str, str], list[Event]] = defaultdict(list)
        for e in ctx.by_kind("auth"):
            if (
                e.outcome != "success"
                or e.attrs.get("logon_type", "").lower() not in _NETWORK_LOGONS
                or e.user in ctx.config.noisy_users
            ):
                continue
            origin = e.attrs.get("src_host") or e.src_ip
            if origin:
                groups[(e.user, origin)].append(e)
        findings: list[Finding] = []
        for (user, origin), events in sorted(groups.items()):
            best: list[Event] = []
            start = 0
            for end in range(len(events)):
                while events[end].time - events[start].time > window:
                    start += 1
                current = events[start : end + 1]
                if len({e.host for e in current}) > len({e.host for e in best}):
                    best = list(current)
            hosts = sorted({e.host for e in best})
            if len(hosts) < t.fanout_min_hosts:
                continue
            known = ctx.baseline.user_hosts.get(user, set())
            fresh = [h for h in hosts if h not in known]
            if ctx.baseline.user_hosts and len(fresh) < math.ceil(len(hosts) / 2):
                continue
            score = (
                55
                + min(20, (len(hosts) - t.fanout_min_hosts) * 4)
                + (10 if ctx.baseline.user_hosts and len(fresh) == len(hosts) else 0)
            )
            findings.append(
                make_finding(
                    self.id,
                    f"{user} reached {len(hosts)} hosts from {origin} in {t.fanout_window_minutes} minutes",
                    best,
                    score=score,
                    tactic=self.tactic,
                    techniques=list(self.techniques),
                    explanation=f"{len(hosts)} distinct hosts, {len(fresh)} of them new for this account.",
                    config=ctx.config,
                    hosts=hosts
                    + (
                        [origin]
                        if not origin.replace(".", "").isdigit() and ":" not in origin
                        else []
                    ),
                    users=[user],
                    ips=[origin] if origin.replace(".", "").isdigit() or ":" in origin else [],
                    details={"hosts": len(hosts), "new_hosts": len(fresh), "origin": origin},
                    benign=[
                        "an administrator running patching or inventory tools",
                        "a jump host used by many teams",
                    ],
                )
            )
        return findings

    def spl(self, t: Thresholds) -> str:
        return (
            "index=auth result=success (logon_type=3 OR logon_type=10)\n| bin _time span="
            + f"{t.fanout_window_minutes}m\n"
            f"| stats dc(host) as hosts by _time user src_host\n| where hosts>={t.fanout_min_hosts}"
        )

    def kql(self, t: Thresholds) -> str:
        return (
            "SecurityEvent\n| where EventID == 4624 and LogonType in (3, 10)\n"
            f"| summarize Hosts=dcount(Computer) by Account, IpAddress, bin(TimeGenerated, {t.fanout_window_minutes}m)\n| where Hosts >= {t.fanout_min_hosts}"
        )
